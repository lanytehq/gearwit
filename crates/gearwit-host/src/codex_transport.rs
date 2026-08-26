// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 3 Leaps, LLC

//! Private, bounded stdio transport for one local Codex app-server process.

use serde_json::{Value, json};
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(unix)]
use nix::fcntl::{FcntlArg, OFlag, fcntl};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

const VERSION: &str = "codex-cli 0.149.1";
const CLIENT_NAME: &str = "gearwit";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_VERSION: usize = 1024;
const MAX_LINE: usize = 1024 * 1024;
const MAX_FRAME: usize = 1024 * 1024;
const MAX_STDOUT: usize = 1024 * 1024;
const MAX_STDERR: usize = 16 * 1024;
const MAX_NATIVE_REF: usize = 1024;
const MAX_QUEUE: usize = 64;
const MAX_PENDING: usize = 64;
const IO_DEADLINE: Duration = Duration::from_secs(8);
const CLEANUP_DEADLINE: Duration = Duration::from_millis(200);
const GRACE_INTERVAL: Duration = Duration::from_millis(50);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const ANCHOR_SCRIPT: &str = "trap '' TERM; while IFS= read -r _; do :; done";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Error {
    Bounds,
    Malformed,
    Version,
    Identity,
    Group,
    Correlation,
    Ambiguous,
    Deadline,
    Closed,
    Preflight,
    Cleanup,
    Unsupported,
    Native,
    Degraded,
    InconsistentTerminal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bounds => "transport bound exceeded",
            Self::Malformed => "malformed transport frame",
            Self::Version => "unsupported Codex version",
            Self::Identity => "executable identity could not be proven",
            Self::Group => "process group could not be proven",
            Self::Correlation => "response correlation failed",
            Self::Ambiguous => "outbound frame acceptance is ambiguous",
            Self::Deadline => "transport deadline expired",
            Self::Closed => "transport stream is closed",
            Self::Preflight => "Codex version preflight failed",
            Self::Cleanup => "process cleanup could not be proven",
            Self::Unsupported => "Codex transport is unsupported on this platform",
            Self::Native => "Codex returned a native error",
            Self::Degraded => "transport notification delivery is degraded",
            Self::InconsistentTerminal => "Codex returned an inconsistent terminal status",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Received {
    Initialized,
    ThreadStarted(NativeRef),
    TurnStarted(NativeRef),
    Notification(Notification),
    ServerRequestRejected,
}

enum Inbound {
    Response { id: u64, result: Value },
    NativeError(u64),
    Notification(Notification),
    ServerRequest(Value),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Notification {
    Signal,
    TurnStarted {
        thread: NativeRef,
        turn: NativeRef,
    },
    Terminal {
        thread: NativeRef,
        turn: NativeRef,
        class: TerminalClass,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalClass {
    Succeeded,
    Interrupted,
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
struct NativeRef(String);

impl fmt::Debug for NativeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeRef([redacted])")
    }
}

impl NativeRef {
    fn parse(value: &Value) -> Result<Self, Error> {
        let value = value.as_str().ok_or(Error::Malformed)?;
        (!value.is_empty() && value.len() <= MAX_NATIVE_REF)
            .then(|| Self(value.to_owned()))
            .ok_or(Error::Bounds)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Initialize,
    ThreadStart,
    TurnStart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    id: u64,
    kind: RequestKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteReceipt {
    Queued,
    WriteAttemptStarted,
    ZeroBytesRejected,
    PossiblyWritten,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriteFailure {
    error: Error,
    receipt: WriteReceipt,
}

struct FrameBuffer(Vec<u8>);

impl FrameBuffer {
    fn new() -> Self {
        Self(Vec::with_capacity(MAX_FRAME))
    }

    fn encode(&mut self, value: &Value) -> Result<&[u8], Error> {
        self.0.clear();
        serde_json::to_writer(&mut *self, value).map_err(|_| Error::Bounds)?;
        self.write_all(b"\n").map_err(|_| Error::Bounds)?;
        Ok(&self.0)
    }
}

impl Write for FrameBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_FRAME.saturating_sub(self.0.len()) {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "frame limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct TransportState {
    line: Vec<u8>,
    frame: FrameBuffer,
    stdout: usize,
    pending: VecDeque<Pending>,
    signals: VecDeque<Notification>,
    ambiguous: bool,
    initialized: bool,
    next_id: u64,
}

impl TransportState {
    fn new() -> Self {
        Self {
            line: Vec::with_capacity(MAX_LINE),
            frame: FrameBuffer::new(),
            stdout: 0,
            pending: VecDeque::with_capacity(MAX_PENDING),
            signals: VecDeque::with_capacity(MAX_QUEUE),
            ambiguous: false,
            initialized: false,
            next_id: 2,
        }
    }

    fn initialize<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        if self.ambiguous {
            return Err(Error::Ambiguous);
        }
        if self.initialized || !self.pending.is_empty() {
            return Err(Error::Bounds);
        }
        self.send(
            writer,
            &json!({
                "id": 1_u64,
                "method": "initialize",
                "params": {"clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}}
            }),
        )?;
        self.pending.push_back(Pending {
            id: 1,
            kind: RequestKind::Initialize,
        });
        Ok(())
    }

    fn start_thread<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        self.send_request(writer, RequestKind::ThreadStart, &json!({}))
    }

    fn start_turn<W: Write>(
        &mut self,
        writer: &mut W,
        thread: &NativeRef,
        managed_input: &Value,
    ) -> Result<(), Error> {
        self.send_request(
            writer,
            RequestKind::TurnStart,
            &json!({"threadId": thread.0, "input": managed_input}),
        )
    }

    fn send_request<W: Write>(
        &mut self,
        writer: &mut W,
        kind: RequestKind,
        params: &Value,
    ) -> Result<(), Error> {
        if self.ambiguous {
            return Err(Error::Ambiguous);
        }
        if !self.initialized {
            return Err(Error::Preflight);
        }
        if !self.pending.is_empty() {
            return Err(Error::Bounds);
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(Error::Bounds)?;
        let method = match kind {
            RequestKind::Initialize => return Err(Error::Unsupported),
            RequestKind::ThreadStart => "thread/start",
            RequestKind::TurnStart => "turn/start",
        };
        self.send(
            writer,
            &json!({"id": id, "method": method, "params": params}),
        )?;
        self.pending.push_back(Pending { id, kind });
        Ok(())
    }

    fn next<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<Received, Error> {
        self.next_until(reader, writer, IO_DEADLINE)
    }

    fn next_until<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        deadline: Duration,
    ) -> Result<Received, Error> {
        let consumed = match read_line_until(reader, &mut self.line, deadline) {
            Ok(consumed) => consumed,
            Err(error) if !self.pending.is_empty() => {
                self.ambiguous = true;
                let _ = error;
                return Err(Error::Ambiguous);
            }
            Err(error) => return Err(error),
        };
        self.stdout = self
            .stdout
            .checked_add(consumed)
            .filter(|total| *total <= MAX_STDOUT)
            .ok_or(Error::Bounds)?;
        let inbound = match classify(&self.line) {
            Ok(inbound) => inbound,
            Err(error) if !self.pending.is_empty() => {
                self.ambiguous = true;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        match inbound {
            Inbound::Response { id, result } => {
                let Some(pending) = self.pending.front().copied() else {
                    return Err(Error::Correlation);
                };
                if pending.id != id {
                    if !self.pending.is_empty() {
                        self.ambiguous = true;
                    }
                    return Err(Error::Correlation);
                }
                let received = match pending.kind {
                    RequestKind::Initialize => {
                        self.ambiguous = false;
                        self.send(writer, &json!({"method": "initialized", "params": {}}))?;
                        self.initialized = true;
                        Received::Initialized
                    }
                    RequestKind::ThreadStart => parse_result_ref(&result, "thread")
                        .map(Received::ThreadStarted)
                        .inspect_err(|_| {
                            self.ambiguous = true;
                        })?,
                    RequestKind::TurnStart => parse_result_ref(&result, "turn")
                        .map(Received::TurnStarted)
                        .inspect_err(|_| {
                            self.ambiguous = true;
                        })?,
                };
                self.ambiguous = false;
                self.pending.pop_front();
                Ok(received)
            }
            Inbound::NativeError(id) => {
                if self.pending.front().map(|pending| pending.id) != Some(id) {
                    if !self.pending.is_empty() {
                        self.ambiguous = true;
                    }
                    return Err(Error::Correlation);
                }
                self.ambiguous = false;
                self.pending.pop_front();
                Err(Error::Native)
            }
            Inbound::Notification(notification) => {
                if !self.initialized {
                    if !self.pending.is_empty() {
                        self.ambiguous = true;
                    }
                    return Err(Error::Correlation);
                }
                if self.signals.len() == MAX_QUEUE {
                    return Err(Error::Degraded);
                }
                self.signals.push_back(notification.clone());
                Ok(Received::Notification(notification))
            }
            Inbound::ServerRequest(id) => {
                self.send(
                    writer,
                    &json!({
                        "id": id,
                        "error": {"code": -32601, "message": "server requests unsupported"}
                    }),
                )?;
                Ok(Received::ServerRequestRejected)
            }
        }
    }

    fn send<W: Write>(&mut self, writer: &mut W, value: &Value) -> Result<WriteReceipt, Error> {
        if self.ambiguous {
            return Err(Error::Ambiguous);
        }
        match self.write(writer, value) {
            Ok(receipt) => Ok(receipt),
            Err(failure) => {
                if matches!(
                    failure.receipt,
                    WriteReceipt::WriteAttemptStarted | WriteReceipt::PossiblyWritten
                ) {
                    self.ambiguous = true;
                    Err(Error::Ambiguous)
                } else {
                    Err(failure.error)
                }
            }
        }
    }

    fn write<W: Write>(
        &mut self,
        writer: &mut W,
        value: &Value,
    ) -> Result<WriteReceipt, WriteFailure> {
        let receipt = WriteReceipt::Queued;
        let frame = self.frame.encode(value).map_err(|error| WriteFailure {
            error,
            receipt: WriteReceipt::ZeroBytesRejected,
        })?;
        debug_assert_eq!(receipt, WriteReceipt::Queued);
        let receipt = WriteReceipt::WriteAttemptStarted;
        let result = write_all_until(writer, frame, IO_DEADLINE);
        if result.is_err() {
            debug_assert_eq!(receipt, WriteReceipt::WriteAttemptStarted);
            return Err(WriteFailure {
                error: Error::Ambiguous,
                receipt: WriteReceipt::PossiblyWritten,
            });
        }
        let _ = receipt;
        Ok(WriteReceipt::PossiblyWritten)
    }

    fn take_signal(&mut self) -> Option<Notification> {
        self.signals.pop_front()
    }
}

fn read_line<R: Read>(reader: &mut R, line: &mut Vec<u8>) -> Result<usize, Error> {
    read_line_until(reader, line, IO_DEADLINE)
}

fn read_line_until<R: Read>(
    reader: &mut R,
    line: &mut Vec<u8>,
    deadline: Duration,
) -> Result<usize, Error> {
    line.clear();
    let mut consumed = 0;
    let mut byte = [0_u8; 1];
    let until = Instant::now() + deadline;
    loop {
        match reader.read(&mut byte) {
            Ok(0) if line.is_empty() => return Err(Error::Closed),
            Ok(0) => return Err(Error::Malformed),
            Ok(_) if byte[0] == b'\n' => return Ok(consumed + 1),
            Ok(_) if line.len() == MAX_LINE => return Err(Error::Bounds),
            Ok(_) => {
                line.push(byte[0]);
                consumed += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err(Error::Deadline);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(Error::Closed),
        }
    }
}

fn write_all_until<W: Write>(
    writer: &mut W,
    mut frame: &[u8],
    deadline: Duration,
) -> Result<(), Error> {
    let until = Instant::now() + deadline;
    while !frame.is_empty() {
        match writer.write(frame) {
            Ok(0) => return Err(Error::Ambiguous),
            Ok(written) => frame = &frame[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err(Error::Deadline);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(Error::Ambiguous),
        }
    }
    loop {
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err(Error::Deadline);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(Error::Ambiguous),
        }
    }
}

fn classify(line: &[u8]) -> Result<Inbound, Error> {
    let value: Value = serde_json::from_slice(line).map_err(|_| Error::Malformed)?;
    let object = value.as_object().ok_or(Error::Malformed)?;
    if object.contains_key("method") {
        return Ok(match object.get("id") {
            Some(id) => Inbound::ServerRequest(id.clone()),
            None => Inbound::Notification(classify_notification(object)?),
        });
    }
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .ok_or(Error::Malformed)?;
    if object.get("result").is_some_and(Value::is_object) {
        return Ok(Inbound::Response {
            id,
            result: object.get("result").cloned().ok_or(Error::Malformed)?,
        });
    }
    object
        .get("error")
        .filter(|error| error.is_object())
        .map(|_| Inbound::NativeError(id))
        .ok_or(Error::Malformed)
}

fn parse_result_ref(result: &Value, field: &str) -> Result<NativeRef, Error> {
    result
        .get(field)
        .and_then(|value| value.get("id"))
        .ok_or(Error::Malformed)
        .and_then(NativeRef::parse)
}

fn classify_notification(object: &serde_json::Map<String, Value>) -> Result<Notification, Error> {
    let method = object.get("method").and_then(Value::as_str);
    match method {
        Some("turn/started") => {
            let params = object.get("params").ok_or(Error::Malformed)?;
            Ok(Notification::TurnStarted {
                thread: params
                    .get("threadId")
                    .ok_or(Error::Malformed)
                    .and_then(NativeRef::parse)?,
                turn: params
                    .get("turn")
                    .and_then(|turn| turn.get("id"))
                    .ok_or(Error::Malformed)
                    .and_then(NativeRef::parse)?,
            })
        }
        Some("turn/completed") => {
            let params = object.get("params").ok_or(Error::Malformed)?;
            let thread = params
                .get("threadId")
                .ok_or(Error::Malformed)
                .and_then(NativeRef::parse)?;
            let turn = params.get("turn").ok_or(Error::Malformed)?;
            let turn_ref = turn
                .get("id")
                .ok_or(Error::Malformed)
                .and_then(NativeRef::parse)?;
            let class = match turn.get("status").and_then(Value::as_str) {
                Some("completed") => TerminalClass::Succeeded,
                Some("interrupted") => TerminalClass::Interrupted,
                Some("failed") => TerminalClass::Failed,
                _ => return Err(Error::InconsistentTerminal),
            };
            Ok(Notification::Terminal {
                thread,
                turn: turn_ref,
                class,
            })
        }
        Some(_) => Ok(Notification::Signal),
        None => Err(Error::Malformed),
    }
}

fn parse_version<R: Read>(reader: &mut R) -> Result<(), Error> {
    parse_version_until(reader, IO_DEADLINE)
}

fn parse_version_until<R: Read>(reader: &mut R, deadline: Duration) -> Result<(), Error> {
    let mut output = Vec::with_capacity(MAX_VERSION);
    let mut chunk = [0_u8; 64];
    let until = Instant::now() + deadline;
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err(Error::Deadline);
                }
                thread::sleep(POLL_INTERVAL);
                continue;
            }
            Err(_) => return Err(Error::Preflight),
        };
        if read == 0 {
            break;
        }
        if read > MAX_VERSION.saturating_sub(output.len()) {
            return Err(Error::Bounds);
        }
        output.extend_from_slice(&chunk[..read]);
    }
    (output == format!("{VERSION}\n").as_bytes())
        .then_some(())
        .ok_or(Error::Version)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

#[cfg(unix)]
fn file_identity(path: &Path) -> Result<FileIdentity, Error> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).map_err(|_| Error::Identity)?;
    metadata.is_file().then_some(()).ok_or(Error::Identity)?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity;

#[cfg(not(unix))]
fn file_identity(_path: &Path) -> Result<FileIdentity, Error> {
    Err(Error::Unsupported)
}

fn resolve(path: &Path) -> Result<PathBuf, Error> {
    if !path.is_absolute() {
        return Err(Error::Identity);
    }
    let path = std::fs::canonicalize(path).map_err(|_| Error::Identity)?;
    std::fs::metadata(&path)
        .map_err(|_| Error::Identity)?
        .is_file()
        .then_some(path)
        .ok_or(Error::Identity)
}

#[cfg(unix)]
fn prove_group_member(pid: u32, group: u32) -> Result<(), Error> {
    let observed = sysprims_session::getpgid(pid).map_err(|_| Error::Group)?;
    let session = sysprims_session::getsid(pid).map_err(|_| Error::Group)?;
    (observed == group && session > 0)
        .then_some(())
        .ok_or(Error::Group)
}

#[cfg(unix)]
fn set_nonblocking<T: AsFd>(handle: &T) -> Result<(), Error> {
    let flags = fcntl(handle, FcntlArg::F_GETFL).map_err(|_| Error::Preflight)?;
    let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
    fcntl(handle, FcntlArg::F_SETFL(flags)).map_err(|_| Error::Preflight)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_nonblocking<T>(_handle: &T) -> Result<(), Error> {
    Err(Error::Unsupported)
}

struct Anchor {
    child: Child,
    input: Option<ChildStdin>,
    group: u32,
    birth_token: u64,
}

fn process_birth_token(pid: u32) -> Result<u64, Error> {
    let until = Instant::now() + CLEANUP_DEADLINE;
    loop {
        if let Some(token) = sysprims_proc::get_process(pid)
            .ok()
            .and_then(|process| process.start_time_unix_ms)
        {
            return Ok(token);
        }
        if Instant::now() >= until {
            return Err(Error::Group);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn reprove_anchor(anchor: &Anchor) -> Result<(), Error> {
    let until = Instant::now() + CLEANUP_DEADLINE;
    loop {
        let matches = sysprims_proc::get_process(anchor.group)
            .ok()
            .is_some_and(|process| process.start_time_unix_ms == Some(anchor.birth_token))
            && prove_group_member(anchor.group, anchor.group).is_ok();
        if matches {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(Error::Group);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_reap(child: &mut Child) -> Result<std::process::ExitStatus, Error> {
    let until = Instant::now() + CLEANUP_DEADLINE;
    loop {
        match child.try_wait().map_err(|_| Error::Cleanup)? {
            Some(status) => return Ok(status),
            None if Instant::now() >= until => return Err(Error::Cleanup),
            None => thread::sleep(POLL_INTERVAL),
        }
    }
}

fn verify_reaped(pid: u32, child: &mut Child) -> Result<(), Error> {
    let _ = wait_for_reap(child)?;
    let until = Instant::now() + CLEANUP_DEADLINE;
    loop {
        if sysprims_proc::is_fully_gone(pid).map_err(|_| Error::Cleanup)? {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(Error::Cleanup);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn close_and_reap_anchor(anchor: &mut Anchor) -> Result<(), Error> {
    anchor.input.take();
    verify_reaped(anchor.group, &mut anchor.child)
}

fn spawn_app_server<F>(anchor: &mut Anchor, spawn: F) -> Result<Child, Error>
where
    F: FnOnce() -> io::Result<Child>,
{
    if let Ok(child) = spawn() {
        Ok(child)
    } else {
        close_and_reap_anchor(anchor)?;
        Err(Error::Preflight)
    }
}

fn spawn_anchor() -> Result<Anchor, Error> {
    #[cfg(not(unix))]
    return Err(Error::Unsupported);
    #[cfg(unix)]
    {
        let executable = resolve(Path::new("/bin/sh"))?;
        let identity = file_identity(&executable)?;
        let mut command = Command::new(&executable);
        command
            .args(["-c", ANCHOR_SCRIPT])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.process_group(0);
        if file_identity(&executable)? != identity {
            return Err(Error::Identity);
        }
        let mut child = command.spawn().map_err(|_| Error::Preflight)?;
        let pid = child.id();
        let birth_token = process_birth_token(pid);
        thread::sleep(GRACE_INTERVAL);
        if birth_token.is_err() || prove_group_member(pid, pid).is_err() {
            drop(child.stdin.take());
            let _ = verify_reaped(pid, &mut child);
            return Err(Error::Group);
        }
        Ok(Anchor {
            input: child.stdin.take(),
            child,
            group: pid,
            birth_token: birth_token.expect("checked"),
        })
    }
}

fn join_group(child: &mut Child, anchor: &Anchor) -> Result<(), Error> {
    #[cfg(not(unix))]
    return Err(Error::Unsupported);
    #[cfg(unix)]
    {
        let pid = child.id();
        // This is applied in the child before exec, avoiding a parent-side setpgid race.
        // The call site configures it before spawning; retain the proof here as a fail-closed check.
        prove_group_member(pid, anchor.group)
    }
}

fn drain_bounded<R: Read>(reader: &mut R, maximum: usize) -> Result<(), Error> {
    let mut total = 0_usize;
    let mut chunk = [0_u8; 128];
    let until = Instant::now() + IO_DEADLINE;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                total = total
                    .checked_add(read)
                    .filter(|size| *size <= maximum)
                    .ok_or(Error::Bounds)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err(Error::Deadline);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(Error::Preflight),
        }
    }
}

fn preflight(executable: &Path) -> Result<FileIdentity, Error> {
    let qualified_identity = file_identity(executable)?;
    let mut anchor = spawn_anchor()?;
    let mut command = Command::new(executable);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(if let Ok(group) = i32::try_from(anchor.group) {
        group
    } else {
        close_and_reap_anchor(&mut anchor)?;
        return Err(Error::Group);
    });
    if file_identity(executable).ok() != Some(qualified_identity) {
        close_and_reap_anchor(&mut anchor)?;
        return Err(Error::Identity);
    }
    let mut child = spawn_app_server(&mut anchor, || command.spawn())?;
    if join_group(&mut child, &anchor).is_err() {
        terminate_group_and_reap(&mut anchor, &mut child)?;
        return Err(Error::Group);
    }
    let Some(mut stdout) = child.stdout.take() else {
        return reject_probe(&mut anchor, &mut child, Error::Preflight);
    };
    let Some(mut stderr) = child.stderr.take() else {
        return reject_probe(&mut anchor, &mut child, Error::Preflight);
    };
    if let Err(error) = set_nonblocking(&stdout).and_then(|()| set_nonblocking(&stderr)) {
        return reject_probe(&mut anchor, &mut child, error);
    }
    let result = parse_version(&mut stdout).and_then(|()| drain_bounded(&mut stderr, MAX_VERSION));
    drop(stdout);
    drop(stderr);
    if result.is_err() {
        return reject_probe(&mut anchor, &mut child, result.expect_err("checked"));
    }
    let Ok(status) = wait_for_reap(&mut child) else {
        return reject_probe(&mut anchor, &mut child, Error::Preflight);
    };
    if !status.success() {
        close_and_reap_anchor(&mut anchor)?;
        return Err(Error::Preflight);
    }
    if file_identity(executable).ok() != Some(qualified_identity) {
        close_and_reap_anchor(&mut anchor)?;
        return Err(Error::Identity);
    }
    close_and_reap_anchor(&mut anchor)?;
    Ok(qualified_identity)
}

fn reject_probe(
    anchor: &mut Anchor,
    child: &mut Child,
    error: Error,
) -> Result<FileIdentity, Error> {
    terminate_group_and_reap(anchor, child).map_err(|_| Error::Cleanup)?;
    Err(error)
}

struct Stderr {
    bytes: Arc<AtomicUsize>,
    overflow: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

fn drain_stderr(mut stderr: ChildStderr) -> Stderr {
    let bytes = Arc::new(AtomicUsize::new(0));
    let overflow = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&bytes);
    let exceeded = Arc::clone(&overflow);
    let read_failed = Arc::clone(&failed);
    let join = thread::spawn(move || {
        let mut chunk = [0_u8; 4096];
        loop {
            let Ok(read) = stderr.read(&mut chunk) else {
                read_failed.store(true, Ordering::Relaxed);
                break;
            };
            if read == 0 {
                return;
            }
            let prior = seen
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(read).min(MAX_STDERR))
                })
                .unwrap_or(MAX_STDERR);
            if prior.saturating_add(read) > MAX_STDERR {
                exceeded.store(true, Ordering::Relaxed);
            }
        }
    });
    Stderr {
        bytes,
        overflow,
        failed,
        join,
    }
}

fn terminate_group_and_reap(anchor: &mut Anchor, child: &mut Child) -> Result<(), Error> {
    let child_pid = child.id();
    reprove_anchor(anchor).map_err(|_| Error::Cleanup)?;
    let terminate_failed = sysprims_signal::terminate_group(anchor.group).is_err();
    thread::sleep(GRACE_INTERVAL);
    reprove_anchor(anchor).map_err(|_| Error::Cleanup)?;
    let kill_failed = sysprims_signal::force_kill_group(anchor.group).is_err();
    anchor.input.take();
    let child_result = verify_reaped(child_pid, child);
    let anchor_result = verify_reaped(anchor.group, &mut anchor.child);
    if terminate_failed || kill_failed || child_result.is_err() || anchor_result.is_err() {
        Err(Error::Cleanup)
    } else {
        Ok(())
    }
}

struct CodexTransport {
    child: Child,
    input: Option<ChildStdin>,
    output: ChildStdout,
    anchor: Anchor,
    stderr: Option<Stderr>,
    state: TransportState,
    cleaned: bool,
}

impl CodexTransport {
    fn start(executable: &Path) -> Result<Self, Error> {
        Self::start_with_before_initialize(executable, |_| Ok(()))
    }

    fn start_with_before_initialize<F>(
        executable: &Path,
        before_initialize: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&mut Child) -> Result<(), Error>,
    {
        let executable = resolve(executable)?;
        let qualified_identity = preflight(&executable)?;
        let mut anchor = spawn_anchor()?;
        let mut command = Command::new(&executable);
        command
            .arg("app-server")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(if let Ok(group) = i32::try_from(anchor.group) {
            group
        } else {
            close_and_reap_anchor(&mut anchor)?;
            return Err(Error::Group);
        });
        if file_identity(&executable).ok() != Some(qualified_identity) {
            close_and_reap_anchor(&mut anchor)?;
            return Err(Error::Identity);
        }
        let mut child = spawn_app_server(&mut anchor, || command.spawn())?;
        if join_group(&mut child, &anchor).is_err() {
            terminate_group_and_reap(&mut anchor, &mut child)?;
            return Err(Error::Group);
        }
        let (Some(input), Some(output), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            terminate_group_and_reap(&mut anchor, &mut child)?;
            return Err(Error::Preflight);
        };
        if let Err(error) = set_nonblocking(&input).and_then(|()| set_nonblocking(&output)) {
            terminate_group_and_reap(&mut anchor, &mut child)?;
            return Err(error);
        }
        let mut transport = Self {
            child,
            input: Some(input),
            output,
            anchor,
            stderr: Some(drain_stderr(stderr)),
            state: TransportState::new(),
            cleaned: false,
        };
        if let Err(error) = before_initialize(&mut transport.child) {
            transport.cleanup()?;
            return Err(error);
        }
        let exited = if let Ok(status) = transport.child.try_wait() {
            status.is_some()
        } else {
            transport.cleanup()?;
            return Err(Error::Closed);
        };
        if exited {
            transport.cleanup()?;
            return Err(Error::Closed);
        }
        let result = transport
            .input
            .as_mut()
            .ok_or(Error::Closed)
            .and_then(|input| transport.state.initialize(input));
        if let Err(error) = result {
            transport.cleanup()?;
            return Err(error);
        }
        Ok(transport)
    }

    fn receive(&mut self) -> Result<Received, Error> {
        if self.stderr.as_ref().is_some_and(|stderr| {
            stderr.overflow.load(Ordering::Relaxed) || stderr.failed.load(Ordering::Relaxed)
        }) {
            return Err(Error::Bounds);
        }
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.next(&mut self.output, input)
    }

    fn start_thread(&mut self) -> Result<(), Error> {
        self.ensure_child_live()?;
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.start_thread(input)
    }

    fn start_turn(&mut self, thread: &NativeRef, managed_input: &Value) -> Result<(), Error> {
        self.ensure_child_live()?;
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.start_turn(input, thread, managed_input)
    }

    fn ensure_child_live(&mut self) -> Result<(), Error> {
        match self.child.try_wait().map_err(|_| Error::Closed)? {
            Some(_) => Err(Error::Closed),
            None => Ok(()),
        }
    }

    fn take_notification(&mut self) -> Option<Notification> {
        self.state.take_signal()
    }

    fn cleanup(&mut self) -> Result<(), Error> {
        if self.cleaned {
            return Ok(());
        }
        self.input.take();
        let result = terminate_group_and_reap(&mut self.anchor, &mut self.child);
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.bytes.load(Ordering::Relaxed);
            if result.is_ok() {
                let _ = stderr.join.join();
            }
        }
        if result.is_ok() {
            self.cleaned = true;
        }
        result
    }
}

impl Drop for CodexTransport {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use nix::sys::stat::Mode;
    #[cfg(unix)]
    use nix::unistd::mkfifo;
    use std::io::Cursor;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    static SCRIPT_ID: AtomicUsize = AtomicUsize::new(0);

    #[cfg(unix)]
    fn test_executable(script: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "gearwit-codex-fixture-{}-{}",
            std::process::id(),
            SCRIPT_ID.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::write(&path, script).expect("write fixture");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("executable fixture");
        path
    }

    #[test]
    fn parse_and_bounds_are_strict() {
        assert!(matches!(
            classify(br#"{"id":1,"result":{}}"#),
            Ok(Inbound::Response { id: 1, .. })
        ));
        assert!(matches!(
            classify(br#"{"method":"notice"}"#),
            Ok(Inbound::Notification(_))
        ));
        assert!(matches!(
            classify(br#"{"id":"x","method":"call"}"#),
            Ok(Inbound::ServerRequest(_))
        ));
        let mut reader = Cursor::new(vec![b'x'; MAX_LINE + 1]);
        let mut line = Vec::with_capacity(MAX_LINE);
        assert_eq!(read_line(&mut reader, &mut line), Err(Error::Bounds));
        assert_eq!(line.capacity(), MAX_LINE);
    }

    #[test]
    fn correlation_and_server_rejection_are_deterministic() {
        let mut state = TransportState::new();
        let mut output = Vec::new();
        state.initialize(&mut output).expect("initialize");
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"id\":1,\"result\":{}}\n"), &mut output),
            Ok(Received::Initialized)
        );
        let initialized = output.rsplit(|byte| *byte == b'\n').nth(1).expect("frame");
        assert_eq!(
            serde_json::from_slice::<Value>(initialized).expect("json"),
            json!({"method":"initialized","params":{}})
        );
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"id\":2,\"result\":{}}\n"), &mut output),
            Err(Error::Correlation)
        );
        assert_eq!(
            state.next(
                &mut Cursor::new(b"{\"id\":\"request\",\"method\":\"call\"}\n"),
                &mut output
            ),
            Ok(Received::ServerRequestRejected)
        );
        let rejection = output.rsplit(|byte| *byte == b'\n').nth(1).expect("frame");
        assert_eq!(
            serde_json::from_slice::<Value>(rejection).expect("json"),
            json!({"id":"request","error":{"code":-32601,"message":"server requests unsupported"}})
        );
    }

    struct FlushFails(Vec<u8>);
    impl Write for FlushFails {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("accepted then failed"))
        }
    }

    #[test]
    fn accepted_write_failure_is_ambiguous_without_replay() {
        let mut state = TransportState::new();
        let mut writer = FlushFails(Vec::new());
        assert_eq!(state.initialize(&mut writer), Err(Error::Ambiguous));
        assert!(state.ambiguous && !writer.0.is_empty());
        assert_eq!(state.initialize(&mut writer), Err(Error::Ambiguous));
    }

    #[test]
    fn initialize_requires_a_correlated_object_before_notifications() {
        let mut state = TransportState::new();
        let mut output = Vec::new();
        state.initialize(&mut output).expect("initialize");
        let initialize = output.split(|byte| *byte == b'\n').next().expect("frame");
        assert_eq!(
            serde_json::from_slice::<Value>(initialize).expect("json"),
            json!({
                "id": 1,
                "method": "initialize",
                "params": {"clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}}
            })
        );
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"method\":\"notice\"}\n"), &mut output),
            Err(Error::Correlation)
        );
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"id\":2,\"result\":{}}\n"), &mut output),
            Err(Error::Correlation)
        );
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"id\":1}\n"), &mut output),
            Err(Error::Malformed)
        );
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"id\":1,\"result\":{}}\n"), &mut output),
            Ok(Received::Initialized)
        );
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"method\":\"notice\"}\n"), &mut output),
            Ok(Received::Notification(Notification::Signal))
        );
    }

    #[test]
    fn failed_server_request_rejection_latches_ambiguity() {
        let mut state = TransportState::new();
        state.initialized = true;
        let mut writer = FlushFails(Vec::new());
        assert_eq!(
            state.next(
                &mut Cursor::new(b"{\"id\":\"request\",\"method\":\"call\"}\n"),
                &mut writer
            ),
            Err(Error::Ambiguous)
        );
        assert!(state.ambiguous && !writer.0.is_empty());
    }

    struct Silent;

    impl Read for Silent {
        fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    struct Delayed {
        waits: usize,
        bytes: Cursor<Vec<u8>>,
    }

    impl Read for Delayed {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.waits > 0 {
                self.waits -= 1;
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.bytes.read(bytes)
        }
    }

    struct BlockedWriter;

    impl Write for BlockedWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    #[test]
    fn silent_or_delayed_io_hits_a_bounded_deadline() {
        let deadline = Duration::from_millis(15);
        let mut line = Vec::new();
        assert_eq!(
            read_line_until(&mut Silent, &mut line, deadline),
            Err(Error::Deadline)
        );
        assert_eq!(
            parse_version_until(&mut Silent, deadline),
            Err(Error::Deadline)
        );
        assert_eq!(
            write_all_until(&mut BlockedWriter, b"frame", deadline),
            Err(Error::Deadline)
        );

        let mut state = TransportState::new();
        let mut output = Vec::new();
        state.initialize(&mut output).expect("initialize");
        assert_eq!(
            state.next_until(&mut Silent, &mut output, deadline),
            Err(Error::Ambiguous)
        );
        assert!(state.ambiguous);

        let mut delayed = Delayed {
            waits: 1,
            bytes: Cursor::new(b"frame\n".to_vec()),
        };
        assert_eq!(
            read_line_until(&mut delayed, &mut line, deadline),
            Ok(b"frame\n".len())
        );
    }

    #[test]
    fn version_must_match_exactly() {
        assert_eq!(
            parse_version(&mut Cursor::new(b"codex-cli 0.149.1\n")),
            Ok(())
        );
        assert_eq!(
            parse_version(&mut Cursor::new(b"codex-cli 0.149.2\n")),
            Err(Error::Version)
        );
        assert_eq!(
            parse_version(&mut Cursor::new(b"codex-cli 0.149.1")),
            Err(Error::Version)
        );
        assert_eq!(
            parse_version(&mut Cursor::new(b"codex-cli 0.149.1\nextra\n")),
            Err(Error::Version)
        );
        assert_eq!(
            drain_bounded(&mut Cursor::new(vec![b'x'; MAX_VERSION + 1]), MAX_VERSION),
            Err(Error::Bounds)
        );
    }

    #[test]
    fn native_errors_reordering_and_delays_are_typed() {
        let mut state = TransportState::new();
        let mut output = Vec::new();
        state.initialize(&mut output).expect("initialize");
        assert_eq!(
            state.next(
                &mut Cursor::new(b"{\"id\":2,\"error\":{\"code\":-32600}}\n"),
                &mut output
            ),
            Err(Error::Correlation)
        );
        assert_eq!(
            state.next(
                &mut Cursor::new(b"{\"id\":1,\"error\":{\"code\":-32600}}\n"),
                &mut output
            ),
            Err(Error::Native)
        );

        let mut state = TransportState::new();
        state.initialize(&mut output).expect("initialize");
        let mut delayed = Delayed {
            waits: 2,
            bytes: Cursor::new(b"{\"id\":1,\"result\":{}}\n".to_vec()),
        };
        assert_eq!(
            state.next_until(&mut delayed, &mut output, Duration::from_millis(50)),
            Ok(Received::Initialized)
        );
    }

    #[test]
    fn malformed_correlated_results_retain_no_replay_state() {
        let mut output = Vec::new();
        let mut thread_state = TransportState::new();
        thread_state.initialized = true;
        thread_state
            .start_thread(&mut output)
            .expect("thread request");
        assert_eq!(
            thread_state.next(
                &mut Cursor::new(b"{\"id\":2,\"result\":{\"thread\":{}}}\n"),
                &mut output
            ),
            Err(Error::Malformed)
        );
        assert!(thread_state.ambiguous && !thread_state.pending.is_empty());
        assert_eq!(
            thread_state.start_thread(&mut output),
            Err(Error::Ambiguous)
        );

        let mut turn_state = TransportState::new();
        turn_state.initialized = true;
        turn_state
            .start_turn(
                &mut output,
                &NativeRef("thread-private".to_owned()),
                &json!([]),
            )
            .expect("turn request");
        let oversized = "x".repeat(MAX_NATIVE_REF + 1);
        let response = format!("{{\"id\":2,\"result\":{{\"turn\":{{\"id\":\"{oversized}\"}}}}}}\n");
        assert_eq!(
            turn_state.next(&mut Cursor::new(response), &mut output),
            Err(Error::Bounds)
        );
        assert!(turn_state.ambiguous && !turn_state.pending.is_empty());
        assert_eq!(
            turn_state.start_turn(
                &mut output,
                &NativeRef("thread-private".to_owned()),
                &json!([])
            ),
            Err(Error::Ambiguous)
        );
    }

    #[test]
    fn requests_require_handshake_single_flight_and_unique_ids() {
        let mut state = TransportState::new();
        let mut output = Vec::new();
        assert_eq!(state.start_thread(&mut output), Err(Error::Preflight));
        assert_eq!(
            state.start_turn(
                &mut output,
                &NativeRef("thread-private".to_owned()),
                &json!([])
            ),
            Err(Error::Preflight)
        );
        state.initialize(&mut output).expect("initialize");
        assert_eq!(state.start_thread(&mut output), Err(Error::Preflight));
        assert_eq!(state.initialize(&mut output), Err(Error::Bounds));
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"id\":1,\"result\":{}}\n"), &mut output),
            Ok(Received::Initialized)
        );

        state.start_thread(&mut output).expect("thread request");
        assert_eq!(state.pending.front().map(|pending| pending.id), Some(2));
        assert_eq!(state.start_thread(&mut output), Err(Error::Bounds));
        assert_eq!(
            state.next(
                &mut Cursor::new(
                    b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\"}}}\n"
                ),
                &mut output
            ),
            Ok(Received::ThreadStarted(NativeRef(
                "thread-private".to_owned()
            )))
        );
        state.start_thread(&mut output).expect("second request");
        assert_eq!(state.pending.front().map(|pending| pending.id), Some(3));
        assert_eq!(state.start_thread(&mut output), Err(Error::Bounds));

        let mut overflow = TransportState::new();
        overflow.initialized = true;
        overflow.next_id = u64::MAX;
        assert_eq!(overflow.start_thread(&mut output), Err(Error::Bounds));
        assert!(overflow.pending.is_empty());
    }

    #[test]
    fn terminal_and_notification_degradation_are_explicit() {
        assert!(matches!(
            classify(
                b"{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"thread-1\",\"turn\":{\"id\":\"turn-1\",\"status\":\"completed\"}}}"
            ),
            Ok(Inbound::Notification(Notification::Terminal {
                class: TerminalClass::Succeeded,
                ..
            }))
        ));
        for (status, expected) in [
            ("interrupted", TerminalClass::Interrupted),
            ("failed", TerminalClass::Failed),
        ] {
            let frame = format!(
                "{{\"method\":\"turn/completed\",\"params\":{{\"threadId\":\"thread-1\",\"turn\":{{\"id\":\"turn-1\",\"status\":\"{status}\"}}}}}}"
            );
            assert!(matches!(
                classify(frame.as_bytes()),
                Ok(Inbound::Notification(Notification::Terminal { class, .. })) if class == expected
            ));
        }
        assert!(matches!(
            classify(b"{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"thread-1\",\"turn\":{\"id\":\"turn-1\",\"status\":\"inProgress\"}}}"),
            Err(Error::InconsistentTerminal)
        ));

        let mut state = TransportState::new();
        state.initialized = true;
        let mut output = Vec::new();
        for _ in 0..MAX_QUEUE {
            assert_eq!(
                state.next(&mut Cursor::new(b"{\"method\":\"notice\"}\n"), &mut output),
                Ok(Received::Notification(Notification::Signal))
            );
        }
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"method\":\"notice\"}\n"), &mut output),
            Err(Error::Degraded)
        );
        for _ in 0..MAX_QUEUE {
            assert_eq!(state.take_signal(), Some(Notification::Signal));
        }
        assert_eq!(state.take_signal(), None);
        assert_eq!(
            state.next(&mut Cursor::new(b"{\"method\":\"notice\"}\n"), &mut output),
            Ok(Received::Notification(Notification::Signal))
        );
    }

    struct FailsImmediately;

    impl Write for FailsImmediately {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct PartialThenFails(bool);

    impl Write for PartialThenFails {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0 {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            } else {
                self.0 = true;
                Ok(bytes.len().min(1))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn all_write_boundaries_preserve_no_replay_disposition() {
        let oversized = json!({"value": "x".repeat(MAX_FRAME)});
        let mut state = TransportState::new();
        assert_eq!(state.send(&mut Vec::new(), &oversized), Err(Error::Bounds));
        assert!(!state.ambiguous);

        let mut state = TransportState::new();
        assert_eq!(
            state.initialize(&mut FailsImmediately),
            Err(Error::Ambiguous)
        );
        assert!(state.ambiguous);

        let mut state = TransportState::new();
        assert_eq!(
            state.initialize(&mut PartialThenFails(false)),
            Err(Error::Ambiguous)
        );
        assert!(state.ambiguous);

        let mut line = Vec::new();
        assert_eq!(
            read_line(&mut Cursor::new(Vec::<u8>::new()), &mut line),
            Err(Error::Closed)
        );
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_replacement_during_the_version_probe() {
        let ready = std::env::temp_dir().join(format!(
            "gearwit-codex-probe-ready-{}-{}",
            std::process::id(),
            SCRIPT_ID.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let proceed = std::env::temp_dir().join(format!(
            "gearwit-codex-probe-proceed-{}-{}",
            std::process::id(),
            SCRIPT_ID.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        mkfifo(&ready, Mode::S_IRUSR | Mode::S_IWUSR).expect("ready fifo");
        mkfifo(&proceed, Mode::S_IRUSR | Mode::S_IWUSR).expect("proceed fifo");
        let executable = test_executable(&format!(
            "#!/bin/sh\nprintf x > '{}'\nIFS= read -r _ < '{}'\nprintf 'codex-cli 0.149.1\\n'\n",
            ready.display(),
            proceed.display()
        ));
        let replacement = test_executable("#!/bin/sh\nprintf 'codex-cli 0.149.1\\n'\n");
        let ready_for_thread = ready.clone();
        let proceed_for_thread = proceed.clone();
        let executable_for_thread = executable.clone();
        let replacement_for_thread = replacement.clone();
        let replace = thread::spawn(move || {
            let mut signal = [0_u8; 1];
            std::fs::File::open(ready_for_thread)
                .expect("open ready")
                .read_exact(&mut signal)
                .expect("read ready");
            std::fs::rename(replacement_for_thread, executable_for_thread)
                .expect("replace executable");
            std::fs::File::options()
                .write(true)
                .open(proceed_for_thread)
                .expect("open proceed")
                .write_all(b"go\n")
                .expect("release probe");
        });
        assert_eq!(preflight(&executable), Err(Error::Identity));
        replace.join().expect("replacement thread");
        let _ = std::fs::remove_file(ready);
        let _ = std::fs::remove_file(proceed);
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn composed_transport_qualifies_private_thread_and_turn_facts() {
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then\n",
            "  printf 'codex-cli 0.149.1\\n'\n",
            "  printf 'bounded diagnostic\\n' >&2\n",
            "  exit 0\n",
            "fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":\"approval\",\"method\":\"item/commandExecution/requestApproval\"}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\"}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"turn\":{\"id\":\"turn-private\"}}}'\n",
            "printf '%s\\n' '{\"method\":\"turn/started\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-private\"}}}'\n",
            "printf '%s\\n' '{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-private\",\"status\":\"completed\"}}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let mut transport = CodexTransport::start(&executable).expect("transport");
        assert_eq!(transport.receive(), Ok(Received::Initialized));
        assert_eq!(transport.receive(), Ok(Received::ServerRequestRejected));
        transport.start_thread().expect("thread request");
        let thread_ref = match transport.receive().expect("thread response") {
            Received::ThreadStarted(thread_ref) => thread_ref,
            other => panic!("unexpected thread response {other:?}"),
        };
        assert_eq!(thread_ref, NativeRef("thread-private".to_owned()));
        transport
            .start_turn(&thread_ref, &json!([]))
            .expect("turn request");
        assert_eq!(
            transport.receive(),
            Ok(Received::TurnStarted(NativeRef("turn-private".to_owned())))
        );
        assert!(matches!(
            transport.receive(),
            Ok(Received::Notification(Notification::TurnStarted { .. }))
        ));
        assert!(matches!(
            transport.take_notification(),
            Some(Notification::TurnStarted { .. })
        ));
        assert!(matches!(
            transport.receive(),
            Ok(Received::Notification(Notification::Terminal {
                class: TerminalClass::Succeeded,
                ..
            }))
        ));
        assert!(matches!(
            transport.take_notification(),
            Some(Notification::Terminal {
                class: TerminalClass::Succeeded,
                ..
            })
        ));
        transport.cleanup().expect("cleanup");
        transport.cleanup().expect("idempotent cleanup");
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn real_transport_child_exit_matrix_is_no_replay() {
        let before_request = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.149.1\\n'; exit 0; fi\n",
            "exit 0\n"
        ));
        let before = CodexTransport::start_with_before_initialize(&before_request, |child| {
            let until = Instant::now() + CLEANUP_DEADLINE;
            loop {
                if child.try_wait().map_err(|_| Error::Closed)?.is_some() {
                    return Ok(());
                }
                if Instant::now() >= until {
                    return Err(Error::Deadline);
                }
                thread::sleep(POLL_INTERVAL);
            }
        });
        assert!(matches!(before, Err(Error::Closed)));
        let _ = std::fs::remove_file(before_request);

        let after_write = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.149.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "exit 0\n"
        ));
        let mut transport = CodexTransport::start(&after_write).expect("after-write transport");
        assert_eq!(transport.receive(), Err(Error::Ambiguous));
        transport.cleanup().expect("cleanup after-write exit");
        let _ = std::fs::remove_file(after_write);

        let during_call = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.149.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "exit 0\n"
        ));
        let mut transport = CodexTransport::start(&during_call).expect("pending-call transport");
        assert_eq!(transport.receive(), Ok(Received::Initialized));
        transport.start_thread().expect("pending thread request");
        assert_eq!(transport.receive(), Err(Error::Ambiguous));
        transport.cleanup().expect("cleanup pending-call exit");
        let _ = std::fs::remove_file(during_call);
    }

    #[cfg(unix)]
    #[test]
    fn anchor_pipe_close_and_group_cleanup_reap_processes() {
        let mut anchor = spawn_anchor().expect("anchor");
        let anchor_pid = anchor.group;
        anchor.input.take();
        assert!(anchor.child.wait().expect("wait").success());
        assert!(sysprims_proc::is_fully_gone(anchor_pid).expect("gone"));

        let mut anchor = spawn_anchor().expect("anchor");
        let shell = resolve(Path::new("/bin/sh")).expect("shell");
        let mut command = Command::new(&shell);
        command
            .args(["-c", "trap '' TERM; while :; do sleep 1; done"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.process_group(i32::try_from(anchor.group).expect("safe group"));
        let mut child = command.spawn().expect("child");
        prove_group_member(child.id(), anchor.group).expect("group");
        reprove_anchor(&anchor).expect("initial anchor proof");
        sysprims_signal::terminate_group(anchor.group).expect("term group");
        thread::sleep(GRACE_INTERVAL);
        reprove_anchor(&anchor).expect("anchor proof after grace");
        sysprims_signal::force_kill_group(anchor.group).expect("kill group");
        anchor.input.take();
        verify_reaped(child.id(), &mut child).expect("app reaped");
        verify_reaped(anchor.group, &mut anchor.child).expect("anchor reaped");
    }

    #[cfg(unix)]
    #[test]
    fn app_spawn_failure_closes_and_reaps_anchor() {
        let mut anchor = spawn_anchor().expect("anchor");
        let anchor_pid = anchor.group;
        let result = spawn_app_server(&mut anchor, || {
            Err(io::Error::other("app-server spawn failed"))
        });
        assert_eq!(result.map(|_| ()), Err(Error::Preflight));
        assert!(sysprims_proc::is_fully_gone(anchor_pid).expect("gone"));
    }
}
