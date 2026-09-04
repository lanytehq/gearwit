// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 3 Leaps, LLC

//! Private, bounded stdio transport for one local Codex app-server process.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};
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
use zeroize::{Zeroize, Zeroizing};

use crate::authority::{ControllerBirthReservation, QuarantinedBirthReservation};
use crate::controller::{
    self, ActiveObservationPrehash, ActiveObservationProof, Controller, ControllerBirthBinding,
    ControllerCommand, ControllerIdleGuard, ControllerProbeError, ControllerReconcileError,
    ControllerWriteError, IdleProbeObservation, IdleProbeResult, IdleProbeScope,
    NativeCoordinateScope, NativeMutationEpoch, NativeTurnFact, NativeWriteDisposition,
    ObservationScope, PersistedTurnCorrelation, PrivateNativeRef, ReconciliationDisposition,
    ReconciliationScope, RequestNonce, SecretNativeCoordinate,
    TerminalClass as ControllerTerminalClass,
};
use crate::persist::{NativeWriteEvidence, Persist, PersistError, ThreadOwnershipState};

#[cfg(unix)]
use nix::fcntl::{FcntlArg, OFlag, fcntl};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

const VERSION: &str = "codex-cli 0.152.1";
const DIALECT: &str = "thread/read-v2";
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

#[derive(Debug, PartialEq, Eq)]
enum Received {
    Initialized,
    ThreadStarted(NativeRef),
    ThreadResumed(ThreadState),
    ThreadRead(ThreadState),
    TurnStarted(NativeRef),
    Notification(Notification),
    ServerRequestRejected,
}

enum Inbound {
    Response { id: u64 },
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
    DegradedTerminal {
        thread: NativeRef,
        turn: NativeRef,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalClass {
    Succeeded,
    Interrupted,
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
struct NativeRef(Zeroizing<Vec<u8>>);

impl fmt::Debug for NativeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeRef([redacted])")
    }
}

impl NativeRef {
    fn parse_borrowed(value: &str) -> Result<Self, Error> {
        (!value.is_empty() && value.len() <= MAX_NATIVE_REF)
            .then(|| Self(Zeroizing::new(value.as_bytes().to_vec())))
            .ok_or(Error::Bounds)
    }

    fn from_validated(value: &str) -> Self {
        debug_assert!(!value.is_empty() && value.len() <= MAX_NATIVE_REF);
        Self(Zeroizing::new(value.as_bytes().to_vec()))
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("native references are parsed from UTF-8")
    }
}

enum ThreadState {
    Idle,
    ActiveTurn(ActiveObservationPrehash),
    Unproven,
}

impl fmt::Debug for ThreadState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Idle => "Idle",
            Self::ActiveTurn(_) => "ActiveTurn([redacted proof prehash])",
            Self::Unproven => "Unproven",
        })
    }
}

impl PartialEq for ThreadState {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Idle, Self::Idle)
                | (Self::ActiveTurn(_), Self::ActiveTurn(_))
                | (Self::Unproven, Self::Unproven)
        )
    }
}

impl Eq for ThreadState {}

#[derive(Clone, PartialEq, Eq)]
struct ThreadToolAttachment {
    helper: PathBuf,
    identity: FileIdentity,
}

impl fmt::Debug for ThreadToolAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ThreadToolAttachment([redacted])")
    }
}

impl ThreadToolAttachment {
    fn at(helper: &Path) -> Result<Self, Error> {
        let helper = resolve(helper)?;
        if helper.as_os_str().len() > MAX_NATIVE_REF {
            return Err(Error::Identity);
        }
        let identity = file_identity(&helper)?;
        Ok(Self { helper, identity })
    }
}

fn attached_thread_params(
    attachment: &ThreadToolAttachment,
    thread: Option<&NativeRef>,
) -> Result<Value, Error> {
    if file_identity(&attachment.helper)? != attachment.identity {
        return Err(Error::Identity);
    }
    let helper = attachment.helper.to_str().ok_or(Error::Identity)?;
    let mut params = json!({
        "config": {
            "mcp_servers": {
                "gearwit_claimed_batch": {
                    "command": helper,
                    "args": []
                }
            }
        }
    });
    if let Some(thread) = thread {
        params
            .as_object_mut()
            .expect("attachment params are an object")
            .insert(
                "threadId".to_owned(),
                Value::String(thread.as_str().to_owned()),
            );
    }
    Ok(params)
}

#[derive(Serialize)]
struct ClientRequest<'a, T: Serialize> {
    id: u64,
    method: &'a str,
    params: &'a T,
}

#[derive(Serialize)]
struct AttachedConfig<'a> {
    mcp_servers: AttachedServers<'a>,
}

#[derive(Serialize)]
struct AttachedServers<'a> {
    gearwit_claimed_batch: AttachedServer<'a>,
}

#[derive(Serialize)]
struct AttachedServer<'a> {
    command: &'a str,
    args: &'static [&'static str],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResumeParams<'a> {
    thread_id: &'a str,
    config: AttachedConfig<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadParams<'a> {
    thread_id: &'a str,
    include_turns: bool,
}

#[derive(Serialize)]
struct TurnInput<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    text: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TurnParams<'a> {
    thread_id: &'a str,
    input: [TurnInput<'a>; 1],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Initialize,
    ThreadStart,
    ThreadResume,
    ThreadRead,
    TurnStart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    id: u64,
    kind: RequestKind,
    thread: Option<NativeRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteReceipt {
    ProvenNotWritten,
    PossiblyWritten,
    Written,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriteFailure {
    error: Error,
    receipt: WriteReceipt,
}

fn failed_write_disposition(failure: WriteFailure) -> NativeWriteDisposition {
    if failure.receipt == WriteReceipt::ProvenNotWritten {
        NativeWriteDisposition::ProvenNotAccepted
    } else {
        NativeWriteDisposition::Unknown
    }
}

#[derive(Debug)]
struct PreparedTurn {
    id: u64,
}

struct FrameBuffer(Zeroizing<Vec<u8>>);

impl FrameBuffer {
    fn new() -> Self {
        Self(Zeroizing::new(Vec::with_capacity(MAX_FRAME)))
    }

    fn encode<T: Serialize>(&mut self, value: &T) -> Result<&[u8], Error> {
        self.0.zeroize();
        self.0.clear();
        serde_json::to_writer(&mut *self, value).map_err(|_| Error::Bounds)?;
        self.write_all(b"\n").map_err(|_| Error::Bounds)?;
        Ok(&self.0)
    }

    fn wipe(&mut self) {
        self.0.zeroize();
        self.0.clear();
    }
}

impl Drop for FrameBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
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
    line: Zeroizing<Vec<u8>>,
    frame: FrameBuffer,
    stdout: usize,
    pending: VecDeque<Pending>,
    notifications: VecDeque<Notification>,
    ambiguous: bool,
    initialized: bool,
    next_id: u64,
}

impl TransportState {
    fn new() -> Self {
        Self {
            line: Zeroizing::new(Vec::with_capacity(MAX_LINE)),
            frame: FrameBuffer::new(),
            stdout: 0,
            pending: VecDeque::with_capacity(MAX_PENDING),
            notifications: VecDeque::with_capacity(MAX_QUEUE),
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
            thread: None,
        });
        Ok(())
    }

    fn start_thread<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        self.send_request(writer, RequestKind::ThreadStart, &json!({}), None)
    }

    fn start_attached_thread<W: Write>(
        &mut self,
        writer: &mut W,
        attachment: &ThreadToolAttachment,
    ) -> Result<(), Error> {
        self.send_request(
            writer,
            RequestKind::ThreadStart,
            &attached_thread_params(attachment, None)?,
            None,
        )
    }

    fn resume_thread<W: Write>(
        &mut self,
        writer: &mut W,
        thread: &NativeRef,
        attachment: &ThreadToolAttachment,
    ) -> Result<(), Error> {
        if file_identity(&attachment.helper)? != attachment.identity {
            return Err(Error::Identity);
        }
        let helper = attachment.helper.to_str().ok_or(Error::Identity)?;
        self.send_request(
            writer,
            RequestKind::ThreadResume,
            &ResumeParams {
                thread_id: thread.as_str(),
                config: AttachedConfig {
                    mcp_servers: AttachedServers {
                        gearwit_claimed_batch: AttachedServer {
                            command: helper,
                            args: &[],
                        },
                    },
                },
            },
            Some(thread.clone()),
        )
    }

    fn read_thread<W: Write>(&mut self, writer: &mut W, thread: &NativeRef) -> Result<(), Error> {
        self.send_request(
            writer,
            RequestKind::ThreadRead,
            &ReadParams {
                thread_id: thread.as_str(),
                include_turns: true,
            },
            Some(thread.clone()),
        )
    }

    fn start_turn<W: Write>(
        &mut self,
        writer: &mut W,
        thread: &NativeRef,
        managed_input: &str,
    ) -> Result<(), Error> {
        self.send_request(
            writer,
            RequestKind::TurnStart,
            &TurnParams {
                thread_id: thread.as_str(),
                input: [TurnInput {
                    kind: "text",
                    text: managed_input,
                }],
            },
            None,
        )
    }

    fn prepare_turn(
        &mut self,
        thread: &NativeRef,
        managed_input: &str,
    ) -> Result<PreparedTurn, Error> {
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
        if let Err(error) = self.frame.encode(&ClientRequest {
            id,
            method: "turn/start",
            params: &TurnParams {
                thread_id: thread.as_str(),
                input: [TurnInput {
                    kind: "text",
                    text: managed_input,
                }],
            },
        }) {
            self.frame.wipe();
            return Err(error);
        }
        Ok(PreparedTurn { id })
    }

    fn discard_prepared_turn(&mut self) {
        self.frame.wipe();
    }

    #[allow(clippy::needless_pass_by_value)] // Consuming the permit prevents frame redispatch.
    fn dispatch_prepared_turn<W: Write>(
        &mut self,
        writer: &mut W,
        prepared: PreparedTurn,
    ) -> Result<WriteReceipt, WriteFailure> {
        let PreparedTurn { id } = prepared;
        let result = write_all_until(writer, &self.frame.0, IO_DEADLINE);
        self.frame.wipe();
        match &result {
            Ok(WriteReceipt::Written)
            | Err(WriteFailure {
                receipt: WriteReceipt::PossiblyWritten,
                ..
            }) => {
                self.ambiguous = result.is_err();
                self.pending.push_back(Pending {
                    id,
                    kind: RequestKind::TurnStart,
                    thread: None,
                });
            }
            Ok(WriteReceipt::ProvenNotWritten | WriteReceipt::PossiblyWritten)
            | Err(WriteFailure {
                receipt: WriteReceipt::ProvenNotWritten | WriteReceipt::Written,
                ..
            }) => {}
        }
        result
    }

    fn send_request<W: Write, T: Serialize>(
        &mut self,
        writer: &mut W,
        kind: RequestKind,
        params: &T,
        thread: Option<NativeRef>,
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
            RequestKind::ThreadResume => "thread/resume",
            RequestKind::ThreadRead => "thread/read",
            RequestKind::TurnStart => "turn/start",
        };
        self.send(writer, &ClientRequest { id, method, params })?;
        self.pending.push_back(Pending { id, kind, thread });
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
        if self.pending.is_empty()
            && let Some(notification) = self.notifications.pop_front()
        {
            return Ok(Received::Notification(notification));
        }
        let until = Instant::now() + deadline;
        loop {
            let remaining = until.saturating_duration_since(Instant::now());
            let consumed = match read_line_until(reader, &mut self.line, remaining) {
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
                    self.line.zeroize();
                    self.line.clear();
                    return Err(error);
                }
                Err(error) => {
                    self.line.zeroize();
                    self.line.clear();
                    return Err(error);
                }
            };
            let outcome = self.handle_inbound(writer, inbound);
            self.line.zeroize();
            self.line.clear();
            match outcome {
                Ok(Some(received)) => return Ok(received),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn handle_inbound<W: Write>(
        &mut self,
        writer: &mut W,
        inbound: Inbound,
    ) -> Result<Option<Received>, Error> {
        match inbound {
            Inbound::Response { id } => {
                let Some(pending) = self.pending.front().cloned() else {
                    return Err(Error::Correlation);
                };
                if pending.id == id {
                    let received = match parse_response(&self.line, &pending) {
                        Ok(received) => received,
                        Err(error) => {
                            self.ambiguous = true;
                            return Err(error);
                        }
                    };
                    self.ambiguous = false;
                    if matches!(received, Received::Initialized) {
                        self.send(writer, &json!({"method": "initialized", "params": {}}))?;
                        self.initialized = true;
                    }
                    self.pending.pop_front();
                    Ok(Some(received))
                } else {
                    self.ambiguous |= !self.pending.is_empty();
                    Err(Error::Correlation)
                }
            }
            Inbound::NativeError(id) => {
                if self.pending.front().map(|pending| pending.id) == Some(id) {
                    self.ambiguous = false;
                    self.pending.pop_front();
                    Err(Error::Native)
                } else {
                    self.ambiguous |= !self.pending.is_empty();
                    Err(Error::Correlation)
                }
            }
            Inbound::Notification(notification) => {
                if !self.initialized {
                    self.ambiguous |= !self.pending.is_empty();
                    Err(Error::Correlation)
                } else if self.pending.is_empty() {
                    Ok(Some(Received::Notification(notification)))
                } else if self.notifications.len() == MAX_QUEUE {
                    Err(Error::Degraded)
                } else {
                    self.notifications.push_back(notification);
                    Ok(None)
                }
            }
            Inbound::ServerRequest(id) => {
                self.send(
                    writer,
                    &json!({
                        "id": id,
                        "error": {"code": -32601, "message": "server requests unsupported"}
                    }),
                )?;
                Ok(self
                    .pending
                    .is_empty()
                    .then_some(Received::ServerRequestRejected))
            }
        }
    }

    fn send<W: Write, T: Serialize>(
        &mut self,
        writer: &mut W,
        value: &T,
    ) -> Result<WriteReceipt, Error> {
        if self.ambiguous {
            return Err(Error::Ambiguous);
        }
        match self.write(writer, value) {
            Ok(receipt) => Ok(receipt),
            Err(failure) => {
                if matches!(failure.receipt, WriteReceipt::PossiblyWritten) {
                    self.ambiguous = true;
                    Err(Error::Ambiguous)
                } else {
                    Err(failure.error)
                }
            }
        }
    }

    fn write<W: Write, T: Serialize>(
        &mut self,
        writer: &mut W,
        value: &T,
    ) -> Result<WriteReceipt, WriteFailure> {
        let frame = self.frame.encode(value).map_err(|error| WriteFailure {
            error,
            receipt: WriteReceipt::ProvenNotWritten,
        })?;
        let result = write_all_until(writer, frame, IO_DEADLINE);
        self.frame.wipe();
        result
    }
}

impl Drop for TransportState {
    fn drop(&mut self) {
        self.line.zeroize();
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
    line.zeroize();
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
) -> Result<WriteReceipt, WriteFailure> {
    let until = Instant::now() + deadline;
    let mut wrote_bytes = false;
    while !frame.is_empty() {
        match writer.write(frame) {
            Ok(0) => {
                return Err(WriteFailure {
                    error: Error::Ambiguous,
                    receipt: if wrote_bytes {
                        WriteReceipt::PossiblyWritten
                    } else {
                        WriteReceipt::ProvenNotWritten
                    },
                });
            }
            Ok(written) => {
                wrote_bytes = true;
                frame = &frame[written..];
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err(WriteFailure {
                        error: Error::Deadline,
                        receipt: if wrote_bytes {
                            WriteReceipt::PossiblyWritten
                        } else {
                            WriteReceipt::ProvenNotWritten
                        },
                    });
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                return Err(WriteFailure {
                    error: Error::Closed,
                    receipt: if wrote_bytes {
                        WriteReceipt::PossiblyWritten
                    } else {
                        WriteReceipt::ProvenNotWritten
                    },
                });
            }
        }
    }
    loop {
        match writer.flush() {
            Ok(()) => return Ok(WriteReceipt::Written),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err(WriteFailure {
                        error: Error::Deadline,
                        receipt: WriteReceipt::PossiblyWritten,
                    });
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                return Err(WriteFailure {
                    error: Error::Ambiguous,
                    receipt: WriteReceipt::PossiblyWritten,
                });
            }
        }
    }
}

#[derive(Deserialize)]
struct BorrowedEnvelope<'a> {
    #[serde(borrow)]
    id: Option<&'a RawValue>,
    #[serde(borrow)]
    method: Option<&'a str>,
    #[serde(borrow)]
    result: Option<&'a RawValue>,
    #[serde(borrow)]
    error: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct BorrowedId<'a> {
    #[serde(borrow)]
    id: &'a str,
}

#[derive(Deserialize)]
struct BorrowedThreadRefResult<'a> {
    #[serde(borrow)]
    thread: BorrowedId<'a>,
}

#[derive(Deserialize)]
struct BorrowedTurnRefResult<'a> {
    #[serde(borrow)]
    turn: BorrowedId<'a>,
}

#[derive(Deserialize)]
struct BorrowedThreadResult<'a> {
    #[serde(borrow)]
    thread: BorrowedThread<'a>,
}

#[derive(Deserialize)]
struct BorrowedThread<'a> {
    #[serde(borrow)]
    id: &'a str,
    #[serde(borrow)]
    status: Option<BorrowedThreadStatus<'a>>,
    #[serde(borrow)]
    turns: Option<Vec<BorrowedTurn<'a>>>,
}

#[derive(Deserialize)]
struct BorrowedThreadStatus<'a> {
    #[serde(rename = "type", borrow)]
    kind: &'a str,
    #[serde(rename = "activeFlags", borrow)]
    active_flags: Option<Vec<&'a str>>,
}

#[derive(Deserialize)]
struct BorrowedTurn<'a> {
    #[serde(borrow)]
    id: Option<&'a str>,
    #[serde(borrow)]
    status: Option<&'a str>,
}

#[derive(Deserialize)]
struct BorrowedNotification<'a> {
    #[serde(borrow)]
    method: &'a str,
    #[serde(borrow)]
    params: BorrowedNotificationParams<'a>,
}

#[derive(Deserialize)]
struct BorrowedNotificationParams<'a> {
    #[serde(rename = "threadId", borrow)]
    thread_id: &'a str,
    #[serde(borrow)]
    turn: BorrowedTurn<'a>,
}

fn raw_object(value: &RawValue) -> bool {
    value.get().trim_start().starts_with('{')
}

fn classify(line: &[u8]) -> Result<Inbound, Error> {
    let envelope: BorrowedEnvelope<'_> =
        serde_json::from_slice(line).map_err(|_| Error::Malformed)?;
    if let Some(method) = envelope.method {
        return if let Some(id) = envelope.id {
            let id = serde_json::from_str(id.get()).map_err(|_| Error::Malformed)?;
            Ok(Inbound::ServerRequest(id))
        } else {
            classify_notification(line, method).map(Inbound::Notification)
        };
    }
    let id = envelope
        .id
        .and_then(|id| serde_json::from_str::<u64>(id.get()).ok())
        .filter(|id| *id > 0)
        .ok_or(Error::Malformed)?;
    if envelope.result.is_some_and(raw_object) {
        return Ok(Inbound::Response { id });
    }
    envelope
        .error
        .filter(|error| raw_object(error))
        .map(|_| Inbound::NativeError(id))
        .ok_or(Error::Malformed)
}

fn parse_response(line: &[u8], pending: &Pending) -> Result<Received, Error> {
    let envelope: BorrowedEnvelope<'_> =
        serde_json::from_slice(line).map_err(|_| Error::Malformed)?;
    let result = envelope.result.ok_or(Error::Malformed)?;
    let received = match pending.kind {
        RequestKind::Initialize => Received::Initialized,
        RequestKind::ThreadStart => {
            let result: BorrowedThreadRefResult<'_> =
                serde_json::from_str(result.get()).map_err(|_| Error::Malformed)?;
            Received::ThreadStarted(NativeRef::parse_borrowed(result.thread.id)?)
        }
        RequestKind::ThreadResume | RequestKind::ThreadRead => {
            let requested = pending.thread.as_ref().ok_or(Error::Correlation)?;
            let state = parse_thread_state_raw(result, requested)?;
            if pending.kind == RequestKind::ThreadResume {
                Received::ThreadResumed(state)
            } else {
                Received::ThreadRead(state)
            }
        }
        RequestKind::TurnStart => {
            let result: BorrowedTurnRefResult<'_> =
                serde_json::from_str(result.get()).map_err(|_| Error::Malformed)?;
            Received::TurnStarted(NativeRef::parse_borrowed(result.turn.id)?)
        }
    };
    Ok(received)
}

fn parse_thread_state_raw(result: &RawValue, requested: &NativeRef) -> Result<ThreadState, Error> {
    let result: BorrowedThreadResult<'_> =
        serde_json::from_str(result.get()).map_err(|_| Error::Malformed)?;
    let returned = NativeRef::parse_borrowed(result.thread.id)?;
    if &returned != requested {
        return Err(Error::Correlation);
    }
    let Some(status) = result.thread.status.as_ref() else {
        return Ok(ThreadState::Unproven);
    };
    match status.kind {
        "idle" => Ok(parse_idle_thread(&result.thread)),
        "active" => {
            let Some(active_flags) = status.active_flags.as_deref() else {
                return Ok(ThreadState::Unproven);
            };
            let Some(active_turn) = parse_active_thread(&result.thread, active_flags) else {
                return Ok(ThreadState::Unproven);
            };
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"gearwit.codex-exact-active.v1\0");
            hash_field(&mut hasher, requested.as_str().as_bytes());
            hash_field(&mut hasher, returned.as_str().as_bytes());
            hash_field(&mut hasher, status.kind.as_bytes());
            for flag in active_flags {
                hash_field(&mut hasher, flag.as_bytes());
            }
            for turn in result.thread.turns.as_deref().unwrap_or_default() {
                hash_field(
                    &mut hasher,
                    turn.id.expect("validated active id").as_bytes(),
                );
                hash_field(
                    &mut hasher,
                    turn.status.expect("validated active status").as_bytes(),
                );
            }
            hash_field(&mut hasher, b"exactly-one-active-turn");
            hash_field(&mut hasher, active_turn.as_bytes());
            hash_field(&mut hasher, VERSION.as_bytes());
            hash_field(&mut hasher, DIALECT.as_bytes());
            Ok(ThreadState::ActiveTurn(ActiveObservationPrehash::new(
                *hasher.finalize().as_bytes(),
            )))
        }
        _ => Ok(ThreadState::Unproven),
    }
}

#[cfg(test)]
fn parse_thread_state(result: &Value, requested: &NativeRef) -> Result<ThreadState, Error> {
    let encoded = serde_json::to_string(result).map_err(|_| Error::Malformed)?;
    let raw = RawValue::from_string(encoded).map_err(|_| Error::Malformed)?;
    parse_thread_state_raw(&raw, requested)
}

fn parse_idle_thread(thread: &BorrowedThread<'_>) -> ThreadState {
    let Some(turns) = thread.turns.as_deref() else {
        return ThreadState::Unproven;
    };
    if turns.len() > MAX_QUEUE
        || turns.iter().any(|turn| {
            turn.id
                .and_then(|id| NativeRef::parse_borrowed(id).ok())
                .is_none()
                || !matches!(turn.status, Some("completed" | "interrupted" | "failed"))
        })
    {
        ThreadState::Unproven
    } else {
        ThreadState::Idle
    }
}

fn parse_active_thread<'a>(
    thread: &'a BorrowedThread<'a>,
    active_flags: &[&str],
) -> Option<&'a str> {
    if active_flags
        .iter()
        .any(|flag| !matches!(*flag, "waitingOnApproval" | "waitingOnUserInput"))
    {
        return None;
    }
    let turns = thread.turns.as_deref()?;
    if turns.len() > MAX_QUEUE {
        return None;
    }
    let mut active = None;
    for turn in turns {
        let id = turn.id?;
        NativeRef::parse_borrowed(id).ok()?;
        match turn.status {
            Some("completed" | "interrupted" | "failed") => {}
            Some("inProgress") if active.is_none() => active = Some(id),
            _ => return None,
        }
    }
    active
}

fn classify_notification(line: &[u8], method: &str) -> Result<Notification, Error> {
    if !matches!(method, "turn/started" | "turn/completed") {
        return Ok(Notification::Signal);
    }
    let notification: BorrowedNotification<'_> =
        serde_json::from_slice(line).map_err(|_| Error::Malformed)?;
    let thread = NativeRef::parse_borrowed(notification.params.thread_id)?;
    let turn = NativeRef::parse_borrowed(notification.params.turn.id.ok_or(Error::Malformed)?)?;
    if notification.method == "turn/started" {
        return Ok(Notification::TurnStarted { thread, turn });
    }
    let class = match notification.params.turn.status {
        Some("completed") => TerminalClass::Succeeded,
        Some("interrupted") => TerminalClass::Interrupted,
        Some("failed") => TerminalClass::Failed,
        _ => return Ok(Notification::DegradedTerminal { thread, turn }),
    };
    Ok(Notification::Terminal {
        thread,
        turn,
        class,
    })
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
        self.receive_until(IO_DEADLINE)
    }

    fn receive_until(&mut self, deadline: Duration) -> Result<Received, Error> {
        if self.stderr.as_ref().is_some_and(|stderr| {
            stderr.overflow.load(Ordering::Relaxed) || stderr.failed.load(Ordering::Relaxed)
        }) {
            return Err(Error::Bounds);
        }
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.next_until(&mut self.output, input, deadline)
    }

    fn start_thread(&mut self) -> Result<(), Error> {
        self.ensure_child_live()?;
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.start_thread(input)
    }

    fn start_attached_thread(&mut self, attachment: &ThreadToolAttachment) -> Result<(), Error> {
        self.ensure_child_live()?;
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.start_attached_thread(input, attachment)
    }

    fn resume_thread(
        &mut self,
        thread: &NativeRef,
        attachment: &ThreadToolAttachment,
    ) -> Result<(), Error> {
        self.ensure_child_live()?;
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.resume_thread(input, thread, attachment)
    }

    fn read_thread(&mut self, thread: &NativeRef) -> Result<(), Error> {
        self.ensure_child_live()?;
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.read_thread(input, thread)
    }

    fn start_turn(&mut self, thread: &NativeRef, managed_input: &str) -> Result<(), Error> {
        self.ensure_child_live()?;
        let input = self.input.as_mut().ok_or(Error::Closed)?;
        self.state.start_turn(input, thread, managed_input)
    }

    fn prepare_turn_frame(
        &mut self,
        thread: &NativeRef,
        managed_input: &str,
    ) -> Result<PreparedTurn, Error> {
        self.ensure_child_live()?;
        if self.input.is_none() {
            return Err(Error::Closed);
        }
        self.state.prepare_turn(thread, managed_input)
    }

    fn ensure_child_live(&mut self) -> Result<(), Error> {
        match self.child.try_wait().map_err(|_| Error::Closed)? {
            Some(_) => Err(Error::Closed),
            None => Ok(()),
        }
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

pub(crate) enum CodexCreateOutcome<P: Persist> {
    Owned {
        reservation: ControllerBirthReservation,
        controller: Box<CodexController<P>>,
    },
    ProvenNotAccepted {
        reservation: ControllerBirthReservation,
        persist: P,
    },
    Unknown {
        reservation: ControllerBirthReservation,
        quarantine: Box<QuarantinedCreate<P>>,
    },
    NotReserved {
        reservation: ControllerBirthReservation,
        persist: P,
    },
}

enum QuarantinedCreateState {
    Pending,
    ExactThread(NativeRef),
}

pub(crate) struct QuarantinedCreate<P: Persist> {
    persist: P,
    transport: CodexTransport,
    attachment: ThreadToolAttachment,
    birth: ControllerBirthBinding,
    create_attempt_id: RequestNonce,
    state: QuarantinedCreateState,
}

pub(crate) enum LateCreateOutcome<P: Persist> {
    Owned {
        reservation: QuarantinedBirthReservation,
        controller: Box<CodexController<P>>,
    },
    ProvenNotAccepted {
        reservation: QuarantinedBirthReservation,
        persist: P,
    },
    StillUnknown {
        reservation: QuarantinedBirthReservation,
        quarantine: Box<QuarantinedCreate<P>>,
    },
}

pub(crate) struct CodexController<P: Persist> {
    persist: P,
    transport: CodexTransport,
    attachment: ThreadToolAttachment,
    birth: ControllerBirthBinding,
    create_attempt_id: RequestNonce,
    thread_ref: PrivateNativeRef,
    epoch: u64,
    lane_probe: Option<RequestNonce>,
    started_turn: Option<PrivateNativeRef>,
    pending_terminal: Option<(PrivateNativeRef, TerminalClass)>,
    reconciling: Option<PersistedTurnCorrelation>,
    terminal: bool,
    lost_reported: bool,
    degraded_reported: bool,
    #[cfg(test)]
    final_check_injection: FinalCheckInjection,
}

#[cfg(test)]
enum FinalCheckInjection {
    None,
    Mutation,
    At(time::OffsetDateTime),
}

impl<P: Persist> QuarantinedCreate<P> {
    pub(crate) fn receive_late(
        mut self,
        reservation: QuarantinedBirthReservation,
    ) -> LateCreateOutcome<P> {
        let (birth_id, create_attempt_id) = reservation.binding();
        if birth_id != &self.birth.birth_id
            || create_attempt_id != &self.create_attempt_id
            || self
                .persist
                .thread_ownership_state(&self.birth.birth_id)
                .ok()
                != Some(ThreadOwnershipState::Unknown {
                    create_attempt_id: self.create_attempt_id.clone(),
                })
        {
            return LateCreateOutcome::StillUnknown {
                reservation,
                quarantine: Box::new(self),
            };
        }
        let thread = match std::mem::replace(&mut self.state, QuarantinedCreateState::Pending) {
            QuarantinedCreateState::ExactThread(thread) => thread,
            QuarantinedCreateState::Pending => match self.transport.receive() {
                Ok(Received::ThreadStarted(thread)) => thread,
                Err(Error::Native) => {
                    return LateCreateOutcome::ProvenNotAccepted {
                        reservation,
                        persist: self.persist,
                    };
                }
                _ => {
                    return LateCreateOutcome::StillUnknown {
                        reservation,
                        quarantine: Box::new(self),
                    };
                }
            },
        };
        let scope = NativeCoordinateScope::Thread {
            birth_id: self.birth.birth_id.clone(),
            create_attempt_id: self.create_attempt_id.clone(),
        };
        let Ok(secret) = SecretNativeCoordinate::thread(thread.as_str()) else {
            self.state = QuarantinedCreateState::ExactThread(thread);
            return LateCreateOutcome::StillUnknown {
                reservation,
                quarantine: Box::new(self),
            };
        };
        let Ok(thread_ref) = self.persist.seal_native_coordinate(&scope, &secret) else {
            drop(secret);
            self.state = QuarantinedCreateState::ExactThread(thread);
            return LateCreateOutcome::StillUnknown {
                reservation,
                quarantine: Box::new(self),
            };
        };
        LateCreateOutcome::Owned {
            reservation,
            controller: Box::new(CodexController::from_owned_parts(
                self.persist,
                self.transport,
                self.attachment,
                self.birth,
                self.create_attempt_id,
                thread_ref,
            )),
        }
    }
}

impl<P: Persist> fmt::Debug for CodexController<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CodexController([redacted owned binding])")
    }
}

impl<P: Persist> CodexController<P> {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn create_owned(
        mut persist: P,
        executable: &Path,
        helper: &Path,
        reservation: ControllerBirthReservation,
    ) -> CodexCreateOutcome<P> {
        let (birth, create_attempt_id) = reservation.binding();
        let (birth, create_attempt_id) = (birth.clone(), create_attempt_id.clone());
        if persist.thread_ownership_state(&birth.birth_id).ok()
            != Some(ThreadOwnershipState::Reserved {
                create_attempt_id: create_attempt_id.clone(),
            })
        {
            return CodexCreateOutcome::NotReserved {
                reservation,
                persist,
            };
        }
        let Ok(attachment) = ThreadToolAttachment::at(helper) else {
            return CodexCreateOutcome::ProvenNotAccepted {
                reservation,
                persist,
            };
        };
        let Ok(mut transport) = CodexTransport::start(executable) else {
            return CodexCreateOutcome::ProvenNotAccepted {
                reservation,
                persist,
            };
        };
        if transport.receive() != Ok(Received::Initialized) {
            return CodexCreateOutcome::ProvenNotAccepted {
                reservation,
                persist,
            };
        }
        if let Err(error) = transport.start_attached_thread(&attachment) {
            return if matches!(error, Error::Ambiguous) {
                CodexCreateOutcome::Unknown {
                    reservation,
                    quarantine: Box::new(QuarantinedCreate {
                        persist,
                        transport,
                        attachment,
                        birth,
                        create_attempt_id,
                        state: QuarantinedCreateState::Pending,
                    }),
                }
            } else {
                CodexCreateOutcome::ProvenNotAccepted {
                    reservation,
                    persist,
                }
            };
        }
        let thread = match transport.receive() {
            Ok(Received::ThreadStarted(thread)) => thread,
            Err(Error::Native) => {
                return CodexCreateOutcome::ProvenNotAccepted {
                    reservation,
                    persist,
                };
            }
            _ => {
                return CodexCreateOutcome::Unknown {
                    reservation,
                    quarantine: Box::new(QuarantinedCreate {
                        persist,
                        transport,
                        attachment,
                        birth,
                        create_attempt_id,
                        state: QuarantinedCreateState::Pending,
                    }),
                };
            }
        };
        let scope = NativeCoordinateScope::Thread {
            birth_id: birth.birth_id.clone(),
            create_attempt_id: create_attempt_id.clone(),
        };
        let Ok(secret) = SecretNativeCoordinate::thread(thread.as_str()) else {
            return CodexCreateOutcome::Unknown {
                reservation,
                quarantine: Box::new(QuarantinedCreate {
                    persist,
                    transport,
                    attachment,
                    birth,
                    create_attempt_id,
                    state: QuarantinedCreateState::ExactThread(thread),
                }),
            };
        };
        let Ok(thread_ref) = persist.seal_native_coordinate(&scope, &secret) else {
            return CodexCreateOutcome::Unknown {
                reservation,
                quarantine: Box::new(QuarantinedCreate {
                    persist,
                    transport,
                    attachment,
                    birth,
                    create_attempt_id,
                    state: QuarantinedCreateState::ExactThread(thread),
                }),
            };
        };
        CodexCreateOutcome::Owned {
            reservation,
            controller: Box::new(Self::from_owned_parts(
                persist,
                transport,
                attachment,
                birth,
                create_attempt_id,
                thread_ref,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn from_owned_parts(
        persist: P,
        transport: CodexTransport,
        attachment: ThreadToolAttachment,
        birth: ControllerBirthBinding,
        create_attempt_id: RequestNonce,
        thread_ref: PrivateNativeRef,
    ) -> Self {
        Self {
            persist,
            transport,
            attachment,
            birth,
            create_attempt_id,
            thread_ref,
            epoch: 0,
            lane_probe: None,
            started_turn: None,
            pending_terminal: None,
            reconciling: None,
            terminal: false,
            lost_reported: false,
            degraded_reported: false,
            #[cfg(test)]
            final_check_injection: FinalCheckInjection::None,
        }
    }

    fn resume_owned(
        persist: P,
        executable: &Path,
        helper: &Path,
        birth: ControllerBirthBinding,
        create_attempt_id: RequestNonce,
        thread_ref: PrivateNativeRef,
    ) -> Result<Self, Error> {
        if persist
            .thread_ownership_state(&birth.birth_id)
            .map_err(map_persist_error)?
            != (ThreadOwnershipState::Owned {
                create_attempt_id: create_attempt_id.clone(),
                thread_ref: thread_ref.clone(),
            })
        {
            return Err(Error::Correlation);
        }
        let attachment = ThreadToolAttachment::at(helper)?;
        let mut transport = CodexTransport::start(executable)?;
        if transport.receive()? != Received::Initialized {
            return Err(Error::Correlation);
        }
        let scope = NativeCoordinateScope::Thread {
            birth_id: birth.birth_id.clone(),
            create_attempt_id: create_attempt_id.clone(),
        };
        let opened = persist
            .open_native_coordinate(&scope, &thread_ref)
            .map_err(map_persist_error)?;
        let thread = NativeRef::from_validated(opened.as_str().map_err(|_| Error::Malformed)?);
        transport.resume_thread(&thread, &attachment)?;
        match transport.receive()? {
            Received::ThreadResumed(_) => {}
            _ => return Err(Error::Correlation),
        }
        drop(thread);
        drop(opened);
        Ok(Self {
            persist,
            transport,
            attachment,
            birth,
            create_attempt_id,
            thread_ref,
            epoch: 0,
            lane_probe: None,
            started_turn: None,
            pending_terminal: None,
            reconciling: None,
            terminal: false,
            lost_reported: false,
            degraded_reported: false,
            #[cfg(test)]
            final_check_injection: FinalCheckInjection::None,
        })
    }

    fn thread_scope(&self) -> NativeCoordinateScope {
        NativeCoordinateScope::Thread {
            birth_id: self.birth.birth_id.clone(),
            create_attempt_id: self.create_attempt_id.clone(),
        }
    }

    fn bump_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
    }

    fn drain_before_mutation(&mut self) -> Result<(), Error> {
        loop {
            match self.transport.receive_until(Duration::ZERO) {
                Err(Error::Deadline) => return Ok(()),
                Err(error) => return Err(error),
                Ok(_) => {
                    self.bump_epoch();
                }
            }
        }
    }

    fn opened_thread(&self) -> Result<crate::controller::OpenedNativeCoordinate, Error> {
        self.persist
            .open_native_coordinate(&self.thread_scope(), &self.thread_ref)
            .map_err(map_persist_error)
    }

    fn seal_turn(
        &mut self,
        scope: &NativeCoordinateScope,
        turn: &NativeRef,
    ) -> Result<PrivateNativeRef, Error> {
        let secret = SecretNativeCoordinate::turn(turn.as_str()).map_err(|_| Error::Bounds)?;
        self.persist
            .seal_native_coordinate(scope, &secret)
            .map_err(map_persist_error)
    }

    fn exact_notification(
        &mut self,
        correlation: &PersistedTurnCorrelation,
        scope: &NativeCoordinateScope,
    ) -> Option<NativeTurnFact> {
        let turn_ref = correlation.turn_ref.as_ref()?;
        if self.started_turn.as_ref() == Some(turn_ref)
            && let Some((pending_turn, class)) = self.pending_terminal.take()
        {
            if pending_turn == *turn_ref {
                self.terminal = true;
                return Some(NativeTurnFact::Terminal {
                    turn_ref: pending_turn,
                    class: terminal_class(class),
                });
            }
            return self.degraded_once();
        }
        let Ok(thread) = self.opened_thread() else {
            return self.degraded_once();
        };
        let Ok(expected_thread) = thread.as_str() else {
            return self.degraded_once();
        };
        let Ok(opened_turn) = self.persist.open_native_coordinate(scope, turn_ref) else {
            return self.degraded_once();
        };
        let Ok(expected_turn) = opened_turn.as_str() else {
            return self.degraded_once();
        };
        loop {
            let notification = match self.transport.receive_until(Duration::ZERO) {
                Ok(Received::Notification(notification)) => notification,
                Err(Error::Closed | Error::Ambiguous) if !self.lost_reported => {
                    self.lost_reported = true;
                    return Some(NativeTurnFact::ControllerLost);
                }
                Err(Error::Malformed | Error::Bounds | Error::Degraded | Error::Correlation) => {
                    return self.degraded_once();
                }
                Err(Error::Deadline) => return None,
                Err(_) => return self.unknown_once(),
                Ok(_) => return self.degraded_once(),
            };
            self.bump_epoch();
            match notification {
                Notification::TurnStarted { thread, turn }
                    if thread.as_str() == expected_thread && turn.as_str() == expected_turn =>
                {
                    if self.started_turn.as_ref() == Some(turn_ref) {
                        continue;
                    }
                    self.started_turn = Some(turn_ref.clone());
                    return Some(NativeTurnFact::Started {
                        turn_ref: turn_ref.clone(),
                    });
                }
                Notification::Terminal {
                    thread,
                    turn,
                    class,
                } if thread.as_str() == expected_thread && turn.as_str() == expected_turn => {
                    if self.terminal {
                        continue;
                    }
                    if self.started_turn.as_ref() != Some(turn_ref) {
                        if self.pending_terminal.is_none() {
                            self.pending_terminal = Some((turn_ref.clone(), class));
                            continue;
                        }
                        return self.degraded_once();
                    }
                    self.terminal = true;
                    return Some(NativeTurnFact::Terminal {
                        turn_ref: turn_ref.clone(),
                        class: terminal_class(class),
                    });
                }
                Notification::DegradedTerminal { thread, turn }
                    if thread.as_str() == expected_thread && turn.as_str() == expected_turn =>
                {
                    return Some(NativeTurnFact::DegradedTerminalObservation);
                }
                Notification::Signal
                | Notification::TurnStarted { .. }
                | Notification::Terminal { .. }
                | Notification::DegradedTerminal { .. } => {}
            }
        }
    }

    fn degraded_once(&mut self) -> Option<NativeTurnFact> {
        if self.degraded_reported {
            None
        } else {
            self.degraded_reported = true;
            Some(NativeTurnFact::DegradedTerminalObservation)
        }
    }

    fn unknown_once(&mut self) -> Option<NativeTurnFact> {
        if self.degraded_reported {
            None
        } else {
            self.degraded_reported = true;
            Some(NativeTurnFact::Unknown)
        }
    }

    #[cfg(test)]
    fn apply_final_check_injection(&mut self) -> Option<time::OffsetDateTime> {
        match std::mem::replace(&mut self.final_check_injection, FinalCheckInjection::None) {
            FinalCheckInjection::None => None,
            FinalCheckInjection::Mutation => {
                self.transport
                    .state
                    .notifications
                    .push_back(Notification::Signal);
                None
            }
            FinalCheckInjection::At(now) => Some(now),
        }
    }
}

fn terminal_class(class: TerminalClass) -> ControllerTerminalClass {
    match class {
        TerminalClass::Succeeded => ControllerTerminalClass::Succeeded,
        TerminalClass::Failed => ControllerTerminalClass::Failed,
        TerminalClass::Interrupted => ControllerTerminalClass::NativeInterrupted,
    }
}

fn map_persist_error(error: PersistError) -> Error {
    match error {
        PersistError::StorageUnavailable => Error::Closed,
        PersistError::Conflict | PersistError::InvalidTransition | PersistError::Unauthorized => {
            Error::Correlation
        }
    }
}

impl<P: Persist> controller::sealed::Sealed for CodexController<P> {}

impl<P: Persist> Controller for CodexController<P> {
    fn probe_idle(
        &mut self,
        scope: IdleProbeScope,
    ) -> Result<IdleProbeResult, ControllerProbeError> {
        let binding = scope.binding;
        let probe_id = binding.challenge_id.clone();
        let observed_at = time::OffsetDateTime::now_utc();
        if binding.attachment.birth_id != self.birth.birth_id
            || binding.thread_ref != self.thread_ref
            || self.lane_probe.is_some()
        {
            return Err(ControllerProbeError::BindingRejected);
        }
        if self.drain_before_mutation().is_err() {
            return Ok(IdleProbeResult::Unproven(IdleProbeObservation::Unproven {
                binding,
                probe_id,
                observed_at,
            }));
        }
        let state = (|| {
            let opened = self.opened_thread()?;
            let thread = NativeRef::from_validated(opened.as_str().map_err(|_| Error::Malformed)?);
            self.transport.read_thread(&thread)?;
            loop {
                match self.transport.receive()? {
                    Received::ThreadRead(ThreadState::ActiveTurn(prehash)) => {
                        let response_epoch = self.epoch;
                        drop(thread);
                        drop(opened);
                        return Ok((ThreadState::Unproven, Some(prehash), response_epoch));
                    }
                    Received::ThreadRead(state) => {
                        let response_epoch = self.epoch;
                        drop(thread);
                        drop(opened);
                        return Ok((state, None, response_epoch));
                    }
                    Received::Notification(_) | Received::ServerRequestRejected => {
                        self.bump_epoch();
                    }
                    _ => return Err(Error::Correlation),
                }
            }
        })();
        if let Ok((_, _, response_epoch)) = &state {
            let drain = self.drain_before_mutation();
            if self.epoch != *response_epoch {
                return Err(ControllerProbeError::EpochInvalidated);
            }
            if drain.is_err() {
                return Ok(IdleProbeResult::Unproven(IdleProbeObservation::Unproven {
                    binding,
                    probe_id,
                    observed_at,
                }));
            }
        }
        Ok(match state {
            Ok((ThreadState::Idle, None, response_epoch)) => {
                let epoch = NativeMutationEpoch {
                    birth_id: self.birth.birth_id.clone(),
                    sequence: response_epoch,
                };
                self.lane_probe = Some(probe_id.clone());
                IdleProbeResult::Idle {
                    observation: IdleProbeObservation::Idle {
                        binding,
                        probe_id: probe_id.clone(),
                        epoch: epoch.clone(),
                        observed_at,
                    },
                    lane: ControllerIdleGuard { probe_id, epoch },
                }
            }
            Ok((_, Some(prehash), response_epoch)) => {
                let epoch = NativeMutationEpoch {
                    birth_id: self.birth.birth_id.clone(),
                    sequence: response_epoch,
                };
                IdleProbeResult::Active(ActiveObservationProof::from_binding(
                    binding,
                    self.create_attempt_id.clone(),
                    epoch,
                    observed_at,
                    prehash,
                    VERSION,
                    DIALECT,
                ))
            }
            Ok((ThreadState::Unproven | ThreadState::ActiveTurn(_), None, _)) | Err(_) => {
                IdleProbeResult::Unproven(IdleProbeObservation::Unproven {
                    binding,
                    probe_id,
                    observed_at,
                })
            }
        })
    }

    fn write_reserved_turn(
        &mut self,
        lane: ControllerIdleGuard,
        command: ControllerCommand,
    ) -> Result<NativeWriteDisposition, ControllerWriteError> {
        let (expected_probe, expected_epoch) = command.expected_probe();
        if self.lane_probe.as_ref() != Some(expected_probe)
            || lane.probe_id != *expected_probe
            || lane.epoch != *expected_epoch
        {
            self.lane_probe = None;
            return Err(ControllerWriteError::BindingRejected);
        }
        let Ok(opened) = self.opened_thread() else {
            self.lane_probe = None;
            return Ok(NativeWriteDisposition::ProvenNotAccepted);
        };
        let Ok(thread) = opened.as_str() else {
            self.lane_probe = None;
            return Ok(NativeWriteDisposition::ProvenNotAccepted);
        };
        let thread = NativeRef::from_validated(thread);
        let managed_input = command.fixed_turn();
        let Ok(prepared_turn) = self.transport.prepare_turn_frame(&thread, &managed_input) else {
            self.lane_probe = None;
            return Ok(NativeWriteDisposition::ProvenNotAccepted);
        };
        drop(managed_input);
        drop(thread);
        drop(opened);
        #[cfg(test)]
        let injected_now = self.apply_final_check_injection();
        if self.drain_before_mutation().is_err() {
            self.transport.state.discard_prepared_turn();
            self.lane_probe = None;
            return Ok(NativeWriteDisposition::ProvenNotAccepted);
        }
        let observed_epoch = NativeMutationEpoch {
            birth_id: self.birth.birth_id.clone(),
            sequence: self.epoch,
        };
        if observed_epoch != *expected_epoch {
            self.transport.state.discard_prepared_turn();
            self.lane_probe = None;
            return Ok(NativeWriteDisposition::IdleEpochInvalidated {
                probe_id: expected_probe.clone(),
                expected_epoch: expected_epoch.clone(),
                observed_epoch,
            });
        }
        let input = self
            .transport
            .input
            .as_mut()
            .expect("prepared turn retains its writer");
        let transport_state = &mut self.transport.state;
        #[cfg(test)]
        let final_now = injected_now.unwrap_or_else(time::OffsetDateTime::now_utc);
        #[cfg(not(test))]
        let final_now = time::OffsetDateTime::now_utc();
        if !command.validate_immutable_binding(&self.birth, &self.thread_ref) {
            transport_state.discard_prepared_turn();
            self.lane_probe = None;
            return Err(ControllerWriteError::BindingRejected);
        }
        if !command.lease_is_current(&self.birth, final_now) {
            transport_state.discard_prepared_turn();
            self.lane_probe = None;
            return Ok(NativeWriteDisposition::ProvenNotAccepted);
        }
        let send = transport_state.dispatch_prepared_turn(input, prepared_turn);
        if let Err(failure) = send {
            self.lane_probe = None;
            let disposition = failed_write_disposition(failure);
            if matches!(disposition, NativeWriteDisposition::Unknown) {
                self.reconciling = Some(command.correlation().clone());
            }
            return Ok(disposition);
        }
        let disposition = match self.transport.receive() {
            Ok(Received::TurnStarted(turn)) => self
                .seal_turn(&command.turn_scope(), &turn)
                .map_or(NativeWriteDisposition::Unknown, |turn_ref| {
                    NativeWriteDisposition::Accepted { turn_ref }
                }),
            Err(Error::Native) => NativeWriteDisposition::ProvenNotAccepted,
            _ => NativeWriteDisposition::Unknown,
        };
        if matches!(disposition, NativeWriteDisposition::Unknown) {
            self.reconciling = Some(command.correlation().clone());
        } else {
            self.reconciling = None;
        }
        self.lane_probe = None;
        Ok(disposition)
    }

    fn poll_exact_observation(&mut self, scope: &ObservationScope) -> Option<NativeTurnFact> {
        let correlation = scope.correlation();
        if correlation.birth_id != self.birth.birth_id || correlation.thread_ref != self.thread_ref
        {
            return None;
        }
        if self.lost_reported {
            return None;
        }
        self.exact_notification(correlation, &scope.turn_scope())
    }

    fn reconcile_exact(
        &mut self,
        scope: &ReconciliationScope,
    ) -> Result<ReconciliationDisposition, ControllerReconcileError> {
        let correlation = scope.correlation();
        let durable_binding = self
            .persist
            .recover_authority_state()
            .ok()
            .is_some_and(|state| {
                state.native_write_evidence.iter().any(|evidence| {
                    evidence.correlation == *correlation
                        && evidence.evidence_ref == scope.evidence_ref
                        && evidence.evidence == NativeWriteEvidence::Unknown
                })
            });
        if self
            .reconciling
            .as_ref()
            .is_some_and(|expected| expected != correlation)
            || !durable_binding
            || correlation.birth_id != self.birth.birth_id
            || correlation.thread_ref != self.thread_ref
        {
            return Err(ControllerReconcileError::BindingRejected);
        }
        let received = self.transport.receive_until(Duration::ZERO);
        Ok(match received {
            Ok(Received::TurnStarted(turn)) => self
                .seal_turn(&scope.turn_scope(), &turn)
                .map_or(ReconciliationDisposition::Unknown, |turn_ref| {
                    ReconciliationDisposition::Accepted { turn_ref }
                }),
            Err(Error::Native) => ReconciliationDisposition::ProvenNotAccepted,
            _ => ReconciliationDisposition::Unknown,
        })
    }
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{CreateResolution, DaemonAuthority, ManagedArmRegistration};
    use crate::controller::{
        ArmId, AttemptId, ControllerAttachment, ControllerBirthId, SignalAction, SignalId,
        VerifierRef,
    };
    use crate::coordinator::{CoordinatedProbe, HostCoordinator, ReservedControllerWrite};
    use crate::persist::{
        FakePersist, PersistedControllerBirth, PreparedDispatchCommit, ReserveBirthOutcome,
        SharedFakePersist, ThreadCreateCommit, ThreadCreateReservation, ThreadCreateResolution,
    };
    #[cfg(unix)]
    use nix::sys::stat::Mode;
    #[cfg(unix)]
    use nix::unistd::mkfifo;
    use std::io::Cursor;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    static SCRIPT_ID: AtomicUsize = AtomicUsize::new(0);

    fn native(value: &str) -> NativeRef {
        NativeRef::from_validated(value)
    }

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

    #[cfg(unix)]
    fn test_tool_attachment() -> (PathBuf, ThreadToolAttachment) {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let attachment = ThreadToolAttachment::at(&helper).expect("qualified attachment");
        (helper, attachment)
    }

    fn reserved_store() -> (FakePersist, ControllerBirthBinding, RequestNonce) {
        let mut persist = FakePersist::default();
        let birth_id = ControllerBirthId::fixture(31);
        let create_attempt_id = RequestNonce::fixture(32);
        let verifier_ref = VerifierRef::fixture(33);
        let lease_until = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
        let binding = ControllerBirthBinding {
            birth_id: birth_id.clone(),
            seat_id: controller::SeatId::new("seat-a").expect("seat"),
            arm_id: ArmId::new("arm-a").expect("arm"),
            generation: 1,
            capability: controller::ManagedCapability::HandleClaimedSignal,
            lease_until,
            verifier_ref: verifier_ref.clone(),
        };
        assert_eq!(
            persist.reserve_controller_birth(
                &PersistedControllerBirth {
                    birth_id: birth_id.clone(),
                    seat_id: binding.seat_id.clone(),
                    arm_id: binding.arm_id.clone(),
                    generation: 1,
                    capability: controller::ManagedCapability::HandleClaimedSignal,
                    lease_until,
                    verifier_ref: verifier_ref.clone(),
                    created_at: time::OffsetDateTime::UNIX_EPOCH,
                    revoked: false,
                },
                &ThreadCreateReservation {
                    birth_id: birth_id.clone(),
                    create_attempt_id: create_attempt_id.clone(),
                    reserved_at: time::OffsetDateTime::UNIX_EPOCH,
                },
            ),
            Ok(ReserveBirthOutcome::Reserved)
        );
        (persist, binding, create_attempt_id)
    }

    fn reserved_authority() -> (
        DaemonAuthority<SharedFakePersist>,
        SharedFakePersist,
        ControllerBirthReservation,
    ) {
        let store = SharedFakePersist::default();
        let now = time::OffsetDateTime::now_utc();
        let mut authority = DaemonAuthority::new(store.clone(), now);
        authority
            .register_managed_arm(ManagedArmRegistration {
                arm_id: "arm-a".to_owned(),
                generation: 1,
                seat_id: "seat-a".to_owned(),
                coverage_until: now + time::Duration::hours(1),
            })
            .expect("arm");
        let reservation = authority.reserve_controller_birth("arm-a").expect("birth");
        (authority, store, reservation)
    }

    fn owned_store() -> (
        FakePersist,
        ControllerBirthBinding,
        RequestNonce,
        PrivateNativeRef,
    ) {
        let (mut persist, birth, create_attempt_id) = reserved_store();
        let scope = NativeCoordinateScope::Thread {
            birth_id: birth.birth_id.clone(),
            create_attempt_id: create_attempt_id.clone(),
        };
        let thread_ref = persist
            .seal_native_coordinate(
                &scope,
                &SecretNativeCoordinate::thread("thread-private").expect("secret"),
            )
            .expect("seal thread");
        persist
            .resolve_thread_create(ThreadCreateCommit {
                birth_id: birth.birth_id.clone(),
                create_attempt_id: create_attempt_id.clone(),
                resolution: ThreadCreateResolution::Owned {
                    thread_ref: thread_ref.clone(),
                },
                evidence_ref: VerifierRef::fixture(34),
            })
            .expect("owned");
        (persist, birth, create_attempt_id, thread_ref)
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn codex_controller_creation_is_exact_or_quarantined_without_replay() {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let exact = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\"}}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (mut authority, store, reservation) = reserved_authority();
        let (birth, create_attempt_id) = reservation.binding();
        let (birth_id, create_attempt_id) = (birth.birth_id.clone(), create_attempt_id.clone());
        let CodexCreateOutcome::Owned {
            reservation,
            mut controller,
        } = CodexController::create_owned(store, &exact, &helper, reservation)
        else {
            panic!("exact owned creation");
        };
        assert!(matches!(
            authority
                .resolve_thread_create(
                    reservation,
                    ThreadCreateResolution::Owned {
                        thread_ref: controller.thread_ref.clone(),
                    },
                )
                .expect("authority resolves owned"),
            CreateResolution::Final(_)
        ));
        assert!(matches!(
            controller
                .persist
                .thread_ownership_state(&birth_id)
                .expect("ownership"),
            ThreadOwnershipState::Owned {
                create_attempt_id: ref stored_create,
                ref thread_ref,
            } if stored_create == &create_attempt_id && thread_ref == &controller.thread_ref
        ));
        let rendered = format!("{controller:?} {:?}", controller.persist);
        assert!(!rendered.contains("thread-private"));
        controller.transport.cleanup().expect("cleanup exact");

        let ambiguous = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{malformed'\n",
            "printf '%s\\n' '{malformed-again'\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-late\"}}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (mut authority, store, reservation) = reserved_authority();
        let CodexCreateOutcome::Unknown {
            reservation,
            quarantine,
        } = CodexController::create_owned(store, &ambiguous, &helper, reservation)
        else {
            panic!("ambiguous create must quarantine");
        };
        let CreateResolution::Unknown { write, reservation } = authority
            .resolve_thread_create(reservation, ThreadCreateResolution::Unknown)
            .expect("durable unknown")
        else {
            panic!("unknown token");
        };
        assert_eq!(write, crate::persist::IdempotentWrite::Recorded);
        let LateCreateOutcome::StillUnknown {
            reservation,
            quarantine,
        } = (*quarantine).receive_late(reservation)
        else {
            panic!("first bounded retry remains unknown");
        };
        let LateCreateOutcome::Owned {
            reservation,
            mut controller,
        } = (*quarantine).receive_late(reservation)
        else {
            panic!("late exact owned");
        };
        authority
            .resolve_quarantined_thread_create(
                reservation,
                ThreadCreateResolution::Owned {
                    thread_ref: controller.thread_ref.clone(),
                },
            )
            .expect("refine unknown to owned");
        controller.transport.cleanup().expect("cleanup late");

        let rejected = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"error\":{\"code\":-32602}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (mut authority, store, reservation) = reserved_authority();
        let (birth, create_attempt_id) = reservation.binding();
        let (birth_id, create_attempt_id) = (birth.birth_id.clone(), create_attempt_id.clone());
        let CodexCreateOutcome::ProvenNotAccepted {
            reservation,
            persist: rejected_store,
        } = CodexController::create_owned(store, &rejected, &helper, reservation)
        else {
            panic!("exact rejection");
        };
        assert!(matches!(
            authority
                .resolve_thread_create(reservation, ThreadCreateResolution::ProvenNotAccepted)
                .expect("authority resolves rejection"),
            CreateResolution::Final(_)
        ));
        assert_eq!(
            rejected_store
                .thread_ownership_state(&birth_id)
                .expect("rejected"),
            ThreadOwnershipState::ProvenNotAccepted { create_attempt_id }
        );

        let late_rejected = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{malformed'\n",
            "printf '%s\\n' '{\"id\":2,\"error\":{\"code\":-32602}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (mut authority, store, reservation) = reserved_authority();
        let CodexCreateOutcome::Unknown {
            reservation,
            quarantine,
        } = CodexController::create_owned(store, &late_rejected, &helper, reservation)
        else {
            panic!("late rejection starts unknown");
        };
        let CreateResolution::Unknown { write, reservation } = authority
            .resolve_thread_create(reservation, ThreadCreateResolution::Unknown)
            .expect("durable unknown before late rejection")
        else {
            panic!("unknown token");
        };
        assert_eq!(write, crate::persist::IdempotentWrite::Recorded);
        let LateCreateOutcome::ProvenNotAccepted {
            reservation,
            persist: _,
        } = (*quarantine).receive_late(reservation)
        else {
            panic!("late exact rejection");
        };
        authority
            .resolve_quarantined_thread_create(
                reservation,
                ThreadCreateResolution::ProvenNotAccepted,
            )
            .expect("refine unknown to rejected");

        let marker = std::env::temp_dir().join(format!(
            "gearwit-create-before-reservation-{}",
            SCRIPT_ID.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let marker_executable =
            test_executable(&format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()));
        let (_authority, _reserved_store, reservation) = reserved_authority();
        assert!(matches!(
            CodexController::create_owned(
                SharedFakePersist::default(),
                &marker_executable,
                &helper,
                reservation,
            ),
            CodexCreateOutcome::NotReserved { .. }
        ));
        assert!(!marker.exists());
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(exact);
        let _ = std::fs::remove_file(ambiguous);
        let _ = std::fs::remove_file(rejected);
        let _ = std::fs::remove_file(late_rejected);
        let _ = std::fs::remove_file(marker_executable);
    }

    #[cfg(unix)]
    #[test]
    fn shared_store_composes_authority_coordinator_and_codex_controller() {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-composed\"}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-composed\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":4,\"result\":{\"turn\":{\"id\":\"turn-composed\"}}}'\n",
            "printf '%s\\n' '{\"method\":\"turn/started\",\"params\":{\"threadId\":\"thread-composed\",\"turn\":{\"id\":\"turn-composed\"}}}'\n",
            "printf '%s\\n' '{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"thread-composed\",\"turn\":{\"id\":\"turn-composed\",\"status\":\"completed\"}}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (mut authority, store, reservation) = reserved_authority();
        let birth_verifier = reservation.binding().0.verifier_ref.clone();
        let CodexCreateOutcome::Owned {
            reservation,
            mut controller,
        } = CodexController::create_owned(store, &executable, &helper, reservation)
        else {
            panic!("owned controller");
        };
        let CreateResolution::Final(create_write) = authority
            .resolve_thread_create(
                reservation,
                ThreadCreateResolution::Owned {
                    thread_ref: controller.thread_ref.clone(),
                },
            )
            .expect("authority resolves create")
        else {
            panic!("final create");
        };
        assert_eq!(create_write, crate::persist::IdempotentWrite::Recorded);
        let admission = authority
            .admit_claim(&crate::authority::ClaimRequest {
                arm_id: "arm-a".to_owned(),
                request_id: "claim-composed".to_owned(),
                signal_id: "signal-composed".to_owned(),
                events: vec![gearwit_protocol::ProviderEvent {
                    provider: "test".to_owned(),
                    event_ref: "event-composed".to_owned(),
                    actor: None,
                    observed_at: "2026-01-15T12:00:00Z".to_owned(),
                    body: "untrusted".to_owned(),
                }],
            })
            .expect("admit");
        assert_ne!(
            authority
                .attachment_verifier(&admission.attempt_id)
                .expect("attachment verifier"),
            &birth_verifier
        );
        let mut coordinator = HostCoordinator::new(authority);
        let scope = coordinator
            .prepare(admission.into_receipt().expect("receipt"))
            .expect("prepare");
        let probe = controller.probe_idle(scope);
        coordinator.set_now(time::OffsetDateTime::now_utc());
        let CoordinatedProbe::Ready(write) = coordinator.authorize_probe(probe).expect("authorize")
        else {
            panic!("reserved write");
        };
        let ReservedControllerWrite { lane, command } = *write;
        let disposition = controller
            .write_reserved_turn(lane, command)
            .expect("controller write");
        assert!(matches!(
            disposition,
            NativeWriteDisposition::Accepted { .. }
        ));
        coordinator
            .conclude_native_write(Ok(disposition))
            .expect("commit accepted");
        assert_eq!(
            coordinator
                .poll_and_record_exact(&mut *controller)
                .expect("record started"),
            Some(crate::persist::IdempotentWrite::Recorded)
        );
        assert_eq!(
            coordinator
                .poll_and_record_exact(&mut *controller)
                .expect("record terminal"),
            Some(crate::persist::IdempotentWrite::Recorded)
        );
        assert!(!coordinator.has_pending_native_authority());
        controller.transport.cleanup().expect("cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn codex_active_probe_records_authority_hold_on_the_shared_store() {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-active\"}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-active\",\"status\":{\"type\":\"active\",\"activeFlags\":[]},\"turns\":[{\"id\":\"turn-active\",\"status\":\"inProgress\"}]}}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (mut authority, store, reservation) = reserved_authority();
        let mut inspection = store.clone();
        let CodexCreateOutcome::Owned {
            reservation,
            mut controller,
        } = CodexController::create_owned(store, &executable, &helper, reservation)
        else {
            panic!("owned controller");
        };
        authority
            .resolve_thread_create(
                reservation,
                ThreadCreateResolution::Owned {
                    thread_ref: controller.thread_ref.clone(),
                },
            )
            .expect("resolve create");
        let admission = authority
            .admit_claim(&crate::authority::ClaimRequest {
                arm_id: "arm-a".to_owned(),
                request_id: "claim-active".to_owned(),
                signal_id: "signal-active".to_owned(),
                events: vec![gearwit_protocol::ProviderEvent {
                    provider: "test".to_owned(),
                    event_ref: "event-active".to_owned(),
                    actor: None,
                    observed_at: "2026-01-15T12:00:00Z".to_owned(),
                    body: "untrusted".to_owned(),
                }],
            })
            .expect("admit");
        let mut coordinator = HostCoordinator::new(authority);
        let scope = coordinator
            .prepare(admission.into_receipt().expect("receipt"))
            .expect("prepare");
        let probe = controller.probe_idle(scope);
        assert!(matches!(&probe, Ok(IdleProbeResult::Active(_))));
        coordinator.set_now(time::OffsetDateTime::now_utc());
        assert!(matches!(
            coordinator
                .authorize_probe(probe)
                .expect("authorize active"),
            CoordinatedProbe::HeldBeforeNativeWrite
        ));
        let snapshot = inspection.recover_authority_state().expect("snapshot");
        assert_eq!(snapshot.active_observations.len(), 1);
        assert_eq!(snapshot.prewrite_conclusions.len(), 1);
        assert!(snapshot.reservations.is_empty());
        controller.transport.cleanup().expect("cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(executable);
    }

    fn reserved_command(
        controller: &mut CodexController<FakePersist>,
        probe_id: RequestNonce,
        epoch: NativeMutationEpoch,
        verifier_ref: VerifierRef,
    ) -> (ControllerCommand, PersistedTurnCorrelation) {
        let correlation = PersistedTurnCorrelation {
            attempt_id: AttemptId::new("attempt-a").expect("attempt"),
            signal_id: SignalId::new("signal-a").expect("signal"),
            birth_id: controller.birth.birth_id.clone(),
            thread_ref: controller.thread_ref.clone(),
            turn_write_id: RequestNonce::fixture(41),
            turn_ref: None,
        };
        let attachment = crate::persist::PersistedControllerAttachment {
            attempt_id: correlation.attempt_id.clone(),
            birth_id: correlation.birth_id.clone(),
            seat_id: controller.birth.seat_id.clone(),
            arm_id: controller.birth.arm_id.clone(),
            generation: controller.birth.generation,
            capability: controller.birth.capability,
            lease_until: controller.birth.lease_until,
            verifier_ref: verifier_ref.clone(),
            revoked: false,
        };
        controller
            .persist
            .admit_claim(
                &crate::persist::ClaimAdmission {
                    record: crate::persist::PersistedClaimRecord {
                        attempt_id: correlation.attempt_id.clone(),
                        request_id: controller::ClaimRequestId::new("claim-a").expect("claim"),
                        arm_id: attachment.arm_id.clone(),
                        generation: 1,
                        signal_id: correlation.signal_id.clone(),
                        event_refs: vec!["event-a".to_owned()],
                        claimed_at: time::OffsetDateTime::UNIX_EPOCH,
                    },
                    events: vec![gearwit_protocol::ProviderEvent {
                        provider: "test".to_owned(),
                        event_ref: "event-a".to_owned(),
                        actor: None,
                        observed_at: "1970-01-01T00:00:00Z".to_owned(),
                        body: "test".to_owned(),
                    }],
                },
                &attachment,
            )
            .expect("claim admission");
        controller
            .persist
            .record_dispatch_prepared(PreparedDispatchCommit {
                correlation: correlation.clone(),
            })
            .expect("prepared");
        let reservation = controller
            .persist
            .reserve_native_turn_write(
                controller::ValidatedIdlePermit {
                    attempt_id: correlation.attempt_id.clone(),
                    signal_id: correlation.signal_id.clone(),
                    birth_id: correlation.birth_id.clone(),
                    thread_ref: correlation.thread_ref.clone(),
                    arm_id: attachment.arm_id.clone(),
                    generation: attachment.generation,
                    capability: attachment.capability,
                    verifier_ref: attachment.verifier_ref.clone(),
                    mutation_epoch: epoch,
                    probe_id,
                    observed_at: time::OffsetDateTime::now_utc(),
                    valid_until: time::OffsetDateTime::now_utc() + time::Duration::seconds(1),
                },
                &correlation,
            )
            .expect("reserve write");
        let command = ControllerCommand::from_reservation(
            ControllerAttachment {
                attempt_id: attachment.attempt_id,
                birth_id: attachment.birth_id,
                arm_id: attachment.arm_id,
                generation: attachment.generation,
                seat_id: attachment.seat_id,
                capability: attachment.capability,
                lease_until: attachment.lease_until,
                verifier_ref,
            },
            SignalAction {
                signal_id: correlation.signal_id.clone(),
            },
            reservation,
        );
        (command, correlation)
    }

    fn idle_probe_scope(
        birth_id: ControllerBirthId,
        thread_ref: PrivateNativeRef,
        verifier_ref: VerifierRef,
    ) -> IdleProbeScope {
        IdleProbeScope {
            binding: controller::ProbeBinding {
                attachment: ControllerAttachment {
                    attempt_id: AttemptId::new("attempt-a").expect("attempt"),
                    birth_id,
                    arm_id: ArmId::new("arm-a").expect("arm"),
                    generation: 1,
                    seat_id: controller::SeatId::new("seat-a").expect("seat"),
                    capability: controller::ManagedCapability::HandleClaimedSignal,
                    lease_until: time::OffsetDateTime::UNIX_EPOCH,
                    verifier_ref,
                },
                signal_id: SignalId::new("signal-a").expect("signal"),
                thread_ref,
                challenge_id: RequestNonce::fixture(42),
            },
        }
    }

    #[cfg(unix)]
    #[test]
    fn codex_controller_resumes_only_owned_thread_and_fails_active_closed() {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"active\",\"activeFlags\":[]},\"turns\":[{\"id\":\"turn-unowned\",\"status\":\"inProgress\"}]}}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (persist, birth, create_attempt_id, thread_ref) = owned_store();
        let verifier_ref = VerifierRef::fixture(43);
        assert!(matches!(
            CodexController::resume_owned(
                persist.clone(),
                &executable,
                &helper,
                birth.clone(),
                create_attempt_id.clone(),
                PrivateNativeRef::fixture(99),
            ),
            Err(Error::Correlation)
        ));
        let mut controller = CodexController::resume_owned(
            persist,
            &executable,
            &helper,
            birth.clone(),
            create_attempt_id,
            thread_ref.clone(),
        )
        .expect("resume owned");
        assert!(matches!(
            controller.probe_idle(idle_probe_scope(
                ControllerBirthId::fixture(99),
                thread_ref.clone(),
                verifier_ref.clone(),
            )),
            Err(ControllerProbeError::BindingRejected)
        ));
        assert_eq!(controller.transport.state.next_id, 3);
        let probe =
            controller.probe_idle(idle_probe_scope(birth.birth_id, thread_ref, verifier_ref));
        assert!(matches!(probe, Ok(IdleProbeResult::Active(_))));
        assert!(controller.transport.state.pending.is_empty());
        controller.transport.cleanup().expect("cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn codex_controller_writes_once_and_filters_exact_turn_lifecycle() {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "IFS= read -r turn_request\n",
            "case \"$turn_request\" in *'Handle the claimed Gearwit signal'*) ;; *) exit 7 ;; esac\n",
            "printf '%s\\n' '{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-private\",\"status\":\"completed\"}}}'\n",
            "printf '%s\\n' '{\"method\":\"turn/started\",\"params\":{\"threadId\":\"thread-other\",\"turn\":{\"id\":\"turn-private\"}}}'\n",
            "printf '%s\\n' '{\"method\":\"turn/started\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-private\"}}}'\n",
            "printf '%s\\n' '{\"id\":4,\"result\":{\"turn\":{\"id\":\"turn-private\"}}}'\n",
            "printf '%s\\n' '{\"method\":\"turn/started\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-private\"}}}'\n",
            "printf '%s\\n' '{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-other\",\"status\":\"failed\"}}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (persist, birth, create_attempt_id, thread_ref) = owned_store();
        let verifier_ref = VerifierRef::fixture(43);
        let mut controller = CodexController::resume_owned(
            persist,
            &executable,
            &helper,
            birth.clone(),
            create_attempt_id,
            thread_ref.clone(),
        )
        .expect("resume");
        let probe = controller.probe_idle(idle_probe_scope(
            birth.birth_id.clone(),
            thread_ref,
            verifier_ref.clone(),
        ));
        let Ok(IdleProbeResult::Idle { lane, observation }) = probe else {
            panic!("idle");
        };
        let IdleProbeObservation::Idle {
            probe_id, epoch, ..
        } = observation
        else {
            panic!("idle observation");
        };
        let (command, mut correlation) =
            reserved_command(&mut controller, probe_id, epoch, verifier_ref);
        let disposition = controller
            .write_reserved_turn(lane, command)
            .expect("controller write");
        let NativeWriteDisposition::Accepted { turn_ref } = disposition else {
            panic!("accepted: {disposition:?}");
        };
        correlation.turn_ref = Some(turn_ref.clone());
        controller
            .persist
            .record_native_turn_fact(crate::persist::NativeTurnFactCommit {
                correlation: correlation.clone(),
                fact: NativeTurnFact::Accepted {
                    turn_ref: turn_ref.clone(),
                },
                evidence_ref: VerifierRef::fixture(44),
            })
            .expect("authority-style accepted commit");
        let scope = ObservationScope {
            correlation,
            evidence_ref: VerifierRef::fixture(43),
        };
        assert_eq!(
            controller.poll_exact_observation(&scope),
            Some(NativeTurnFact::Started {
                turn_ref: turn_ref.clone()
            })
        );
        assert_eq!(
            controller.poll_exact_observation(&scope),
            Some(NativeTurnFact::Terminal {
                turn_ref,
                class: ControllerTerminalClass::Succeeded,
            })
        );
        assert_eq!(controller.poll_exact_observation(&scope), None);
        controller.transport.cleanup().expect("cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn exact_idle_followed_by_event_cannot_establish_an_idle_lane() {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "printf '%s\\n' '{\"method\":\"notice\"}'\n",
            "while IFS= read -r _; do exit 9; done\n"
        ));
        let (persist, birth, create_attempt_id, thread_ref) = owned_store();
        let mut controller = CodexController::resume_owned(
            persist,
            &executable,
            &helper,
            birth.clone(),
            create_attempt_id,
            thread_ref.clone(),
        )
        .expect("resume");

        assert!(matches!(
            controller.probe_idle(idle_probe_scope(
                birth.birth_id,
                thread_ref,
                VerifierRef::fixture(43),
            )),
            Err(ControllerProbeError::EpochInvalidated)
        ));
        assert!(controller.lane_probe.is_none());
        assert_eq!(controller.transport.state.next_id, 4);
        assert!(controller.transport.state.pending.is_empty());
        controller.transport.cleanup().expect("cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn codex_controller_intervening_notification_invalidates_before_turn_bytes() {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "while IFS= read -r _; do exit 9; done\n"
        ));
        let (persist, birth, create_attempt_id, thread_ref) = owned_store();
        let verifier_ref = VerifierRef::fixture(43);
        let mut controller = CodexController::resume_owned(
            persist,
            &executable,
            &helper,
            birth.clone(),
            create_attempt_id,
            thread_ref.clone(),
        )
        .expect("resume");
        let probe = controller.probe_idle(idle_probe_scope(
            birth.birth_id,
            thread_ref,
            verifier_ref.clone(),
        ));
        let Ok(IdleProbeResult::Idle { lane, observation }) = probe else {
            panic!("idle");
        };
        let IdleProbeObservation::Idle {
            probe_id, epoch, ..
        } = observation
        else {
            panic!("idle observation");
        };
        let (command, _) = reserved_command(&mut controller, probe_id, epoch, verifier_ref);
        controller.final_check_injection = FinalCheckInjection::Mutation;
        let Ok(NativeWriteDisposition::IdleEpochInvalidated {
            expected_epoch,
            observed_epoch,
            ..
        }) = controller.write_reserved_turn(lane, command)
        else {
            panic!("notification invalidates idle epoch");
        };
        assert_eq!(observed_epoch.sequence, expected_epoch.sequence + 1);
        assert_eq!(controller.transport.state.next_id, 5);
        assert!(controller.transport.state.pending.is_empty());
        assert!(controller.transport.state.frame.0.is_empty());
        controller.transport.cleanup().expect("cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn lease_expiry_at_final_write_check_emits_no_turn_bytes() {
        let helper = test_executable("#!/bin/sh\nexit 0\n");
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "while IFS= read -r _; do exit 9; done\n"
        ));
        let (persist, birth, create_attempt_id, thread_ref) = owned_store();
        let verifier_ref = VerifierRef::fixture(43);
        let mut controller = CodexController::resume_owned(
            persist,
            &executable,
            &helper,
            birth.clone(),
            create_attempt_id,
            thread_ref.clone(),
        )
        .expect("resume");
        let Ok(IdleProbeResult::Idle { lane, observation }) = controller.probe_idle(
            idle_probe_scope(birth.birth_id, thread_ref, verifier_ref.clone()),
        ) else {
            panic!("idle");
        };
        let IdleProbeObservation::Idle {
            probe_id, epoch, ..
        } = observation
        else {
            panic!("idle observation");
        };
        let (command, _) = reserved_command(&mut controller, probe_id, epoch, verifier_ref);
        controller.final_check_injection = FinalCheckInjection::At(controller.birth.lease_until);

        assert_eq!(
            controller.write_reserved_turn(lane, command),
            Ok(NativeWriteDisposition::ProvenNotAccepted)
        );
        assert_eq!(controller.transport.state.next_id, 5);
        assert!(controller.transport.state.pending.is_empty());
        assert!(controller.transport.state.frame.0.is_empty());
        controller.transport.cleanup().expect("cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(executable);
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
            Err(WriteFailure {
                error: Error::Deadline,
                receipt: WriteReceipt::ProvenNotWritten,
            })
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
    fn raw_transport_buffers_zeroize_in_place() {
        let mut state = TransportState::new();
        state.line.extend_from_slice(b"private-native-line");
        state.line.zeroize();
        assert!(state.line.iter().all(|byte| *byte == 0));

        state.frame.0.extend_from_slice(b"private-native-frame");
        state.frame.0.zeroize();
        assert!(state.frame.0.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn prepared_turn_frame_is_consumed_and_wiped_immediately_after_dispatch() {
        let mut state = TransportState::new();
        state.initialized = true;
        let prepared = state
            .prepare_turn(&native("thread-private"), "fixed input")
            .expect("prepare turn");
        assert!(!state.frame.0.is_empty());
        let mut output = Vec::new();

        assert_eq!(
            state.dispatch_prepared_turn(&mut output, prepared),
            Ok(WriteReceipt::Written)
        );
        assert!(state.frame.0.is_empty());
        assert_eq!(state.pending.len(), 1);
    }

    #[test]
    fn active_response_line_is_erased_before_receive_returns() {
        let mut state = TransportState::new();
        state.initialized = true;
        let mut output = Vec::new();
        state
            .read_thread(&mut output, &native("thread-private"))
            .expect("thread read request");
        let response = b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"active\",\"activeFlags\":[]},\"turns\":[{\"id\":\"turn-private\",\"status\":\"inProgress\"}]}}}\n";

        assert!(matches!(
            state.next(&mut Cursor::new(response), &mut output),
            Ok(Received::ThreadRead(ThreadState::ActiveTurn(_)))
        ));
        assert!(state.line.is_empty());
    }

    #[test]
    fn pending_response_retains_notifications_and_rejects_escaped_native_ids() {
        let mut state = TransportState::new();
        state.initialized = true;
        let mut output = Vec::new();
        state
            .start_turn(&mut output, &native("thread-private"), "test")
            .expect("turn request");
        let frames = concat!(
            "{\"method\":\"turn/completed\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-private\",\"status\":\"completed\"}}}\n",
            "{\"method\":\"turn/started\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-private\"}}}\n",
            "{\"id\":2,\"result\":{\"turn\":{\"id\":\"turn-private\"}}}\n"
        );
        assert_eq!(
            state.next(&mut Cursor::new(frames.as_bytes()), &mut output),
            Ok(Received::TurnStarted(native("turn-private")))
        );
        assert!(matches!(
            state.next(&mut Silent, &mut output),
            Ok(Received::Notification(Notification::Terminal { .. }))
        ));
        assert!(matches!(
            state.next(&mut Silent, &mut output),
            Ok(Received::Notification(Notification::TurnStarted { .. }))
        ));

        let mut unknown = TransportState::new();
        unknown.initialized = true;
        unknown
            .start_turn(&mut output, &native("thread-private"), "test")
            .expect("unknown turn request");
        assert_eq!(
            unknown.next(
                &mut Cursor::new(b"{\"method\":\"turn/started\",\"params\":{\"threadId\":\"thread-private\",\"turn\":{\"id\":\"turn-private\"}}}\n"),
                &mut output,
            ),
            Err(Error::Ambiguous)
        );
        assert_eq!(unknown.notifications.len(), 1);
        assert_eq!(
            unknown.next(
                &mut Cursor::new(b"{\"id\":2,\"result\":{\"turn\":{\"id\":\"turn-private\"}}}\n"),
                &mut output,
            ),
            Ok(Received::TurnStarted(native("turn-private")))
        );
        assert!(matches!(
            unknown.next(&mut Silent, &mut output),
            Ok(Received::Notification(Notification::TurnStarted { .. }))
        ));

        let mut escaped = TransportState::new();
        escaped.initialized = true;
        escaped.start_thread(&mut output).expect("thread request");
        assert_eq!(
            escaped.next(
                &mut Cursor::new(
                    b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread\\u002dprivate\"}}}\n"
                ),
                &mut output,
            ),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn version_must_match_exactly() {
        assert_eq!(
            parse_version(&mut Cursor::new(b"codex-cli 0.152.1\n")),
            Ok(())
        );
        assert_eq!(
            parse_version(&mut Cursor::new(b"codex-cli 0.152.2\n")),
            Err(Error::Version)
        );
        assert_eq!(
            parse_version(&mut Cursor::new(b"codex-cli 0.152.1")),
            Err(Error::Version)
        );
        assert_eq!(
            parse_version(&mut Cursor::new(b"codex-cli 0.152.1\nextra\n")),
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
            .start_turn(&mut output, &native("thread-private"), "test")
            .expect("turn request");
        let oversized = "x".repeat(MAX_NATIVE_REF + 1);
        let response = format!("{{\"id\":2,\"result\":{{\"turn\":{{\"id\":\"{oversized}\"}}}}}}\n");
        assert_eq!(
            turn_state.next(&mut Cursor::new(response), &mut output),
            Err(Error::Bounds)
        );
        assert!(turn_state.ambiguous && !turn_state.pending.is_empty());
        assert_eq!(
            turn_state.start_turn(&mut output, &native("thread-private"), "test"),
            Err(Error::Ambiguous)
        );
    }

    #[test]
    fn requests_require_handshake_single_flight_and_unique_ids() {
        let mut state = TransportState::new();
        let mut output = Vec::new();
        assert_eq!(state.start_thread(&mut output), Err(Error::Preflight));
        assert_eq!(
            state.start_turn(&mut output, &native("thread-private"), "test"),
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
            Ok(Received::ThreadStarted(native("thread-private")))
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
            Ok(Inbound::Notification(Notification::DegradedTerminal { .. }))
        ));

        let mut state = TransportState::new();
        state.initialized = true;
        let mut output = Vec::new();
        for _ in 0..=MAX_QUEUE {
            assert_eq!(
                state.next(&mut Cursor::new(b"{\"method\":\"notice\"}\n"), &mut output),
                Ok(Received::Notification(Notification::Signal))
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn attached_create_and_exact_resume_share_only_the_thread_override() {
        let (helper, attachment) = test_tool_attachment();
        assert_eq!(
            format!("{attachment:?}"),
            "ThreadToolAttachment([redacted])"
        );

        let thread = native("thread-private");
        let mut state = TransportState::new();
        let mut output = Vec::new();
        state.initialize(&mut output).expect("initialize");
        state
            .next(&mut Cursor::new(b"{\"id\":1,\"result\":{}}\n"), &mut output)
            .expect("initialized");
        state
            .start_attached_thread(&mut output, &attachment)
            .expect("attached start");
        state
            .next(
                &mut Cursor::new(
                    b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\"}}}\n",
                ),
                &mut output,
            )
            .expect("started");
        state
            .resume_thread(&mut output, &thread, &attachment)
            .expect("exact resume");
        state
            .next(
                &mut Cursor::new(
                    b"{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}\n",
                ),
                &mut output,
            )
            .expect("resumed");
        state.read_thread(&mut output, &thread).expect("exact read");
        state
            .next(
                &mut Cursor::new(
                    b"{\"id\":4,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}\n",
                ),
                &mut output,
            )
            .expect("read");
        state
            .start_turn(&mut output, &thread, "test")
            .expect("turn start");

        let frames: Vec<Value> = output
            .split(|byte| *byte == b'\n')
            .filter(|frame| !frame.is_empty())
            .map(|frame| serde_json::from_slice(frame).expect("json frame"))
            .collect();
        let initialize = &frames[0];
        let create = &frames[2];
        let resume = &frames[3];
        let read = &frames[4];
        let turn = &frames[5];
        let helper_text = attachment.helper.to_string_lossy();
        assert!(initialize["params"].get("config").is_none());
        assert!(!initialize.to_string().contains(helper_text.as_ref()));
        assert_eq!(create["params"]["config"], resume["params"]["config"]);
        assert_eq!(create["params"].as_object().expect("params").len(), 1);
        assert_eq!(resume["method"], "thread/resume");
        assert_eq!(resume["params"]["threadId"], "thread-private");
        assert_eq!(resume["params"].as_object().expect("params").len(), 2);
        assert!(resume["params"].get("history").is_none());
        assert!(resume["params"].get("path").is_none());
        assert_eq!(
            read,
            &json!({
                "id": 4,
                "method": "thread/read",
                "params": {"threadId": "thread-private", "includeTurns": true}
            })
        );
        assert_eq!(
            turn["params"]["input"],
            json!([{"type": "text", "text": "test"}])
        );
        assert!(!turn.to_string().contains(helper_text.as_ref()));
        let _ = std::fs::remove_file(helper);
    }

    #[cfg(unix)]
    #[test]
    fn replaced_attachment_fails_before_request_bytes() {
        let (helper, attachment) = test_tool_attachment();
        let replacement = test_executable("#!/bin/sh\nexit 1\n");
        std::fs::rename(&replacement, &helper).expect("replace helper");

        let mut state = TransportState::new();
        state.initialized = true;
        let mut output = Vec::new();
        assert_eq!(
            state.resume_thread(&mut output, &native("thread-private"), &attachment,),
            Err(Error::Identity)
        );
        assert!(output.is_empty());
        assert!(state.pending.is_empty());
        let _ = std::fs::remove_file(helper);
    }

    #[test]
    fn exact_thread_state_mapping_is_closed_and_correlated() {
        let requested = native("thread-private");
        assert_eq!(
            parse_thread_state(
                &json!({"thread": {
                    "id": "thread-private",
                    "status": {"type": "idle"},
                    "turns": [{"id": "turn-old", "status": "completed"}]
                }}),
                &requested,
            ),
            Ok(ThreadState::Idle)
        );
        assert!(matches!(
            parse_thread_state(
                &json!({"thread": {
                    "id": "thread-private",
                    "status": {"type": "active", "activeFlags": ["waitingOnApproval"]},
                    "turns": [
                        {"id": "turn-old", "status": "completed"},
                        {"id": "turn-exact", "status": "inProgress"}
                    ]
                }}),
                &requested,
            ),
            Ok(ThreadState::ActiveTurn(_))
        ));
        let first = parse_thread_state(
            &json!({"thread": {
                "id": "thread-private",
                "status": {"type": "active", "activeFlags": ["waitingOnApproval"]},
                "turns": [{"id": "turn-exact", "status": "inProgress"}]
            }}),
            &requested,
        )
        .expect("first active");
        let second = parse_thread_state(
            &json!({"thread": {
                "id": "thread-private",
                "status": {"type": "active", "activeFlags": ["waitingOnUserInput"]},
                "turns": [{"id": "turn-exact", "status": "inProgress"}]
            }}),
            &requested,
        )
        .expect("second active");
        let (ThreadState::ActiveTurn(first), ThreadState::ActiveTurn(second)) = (first, second)
        else {
            panic!("active prehashes");
        };
        assert_ne!(first.bytes(), second.bytes());
        assert_eq!(
            parse_thread_state(
                &json!({"thread": {
                    "id": "thread-unrelated",
                    "status": {"type": "idle"},
                    "turns": []
                }}),
                &requested,
            ),
            Err(Error::Correlation)
        );

        for thread in [
            json!({"id": "thread-private"}),
            json!({"id": "thread-private", "status": {"type": "idle"}}),
            json!({"id": "thread-private", "status": {"type": "idle"}, "turns": [{"id": "turn-1", "status": "inProgress"}]}),
            json!({"id": "thread-private", "status": {"type": "idle"}, "turns": [{"id": "turn-1", "status": "future"}]}),
            json!({"id": "thread-private", "status": {"type": "idle"}, "turns": [{"status": "completed"}]}),
            json!({"id": "thread-private", "status": {"type": "future"}, "turns": []}),
            json!({"id": "thread-private", "status": {"type": "notLoaded"}, "turns": []}),
            json!({"id": "thread-private", "status": {"type": "systemError"}, "turns": []}),
            json!({"id": "thread-private", "status": {"type": "active"}, "turns": []}),
            json!({"id": "thread-private", "status": {"type": "active", "activeFlags": ["future"]}, "turns": [{"id": "turn-1", "status": "inProgress"}]}),
            json!({"id": "thread-private", "status": {"type": "active", "activeFlags": []}, "turns": []}),
            json!({"id": "thread-private", "status": {"type": "active", "activeFlags": []}, "turns": [{"status": "completed"}, {"id": "turn-1", "status": "inProgress"}]}),
            json!({"id": "thread-private", "status": {"type": "active", "activeFlags": []}, "turns": [{"id": "turn-1", "status": "future"}]}),
            json!({"id": "thread-private", "status": {"type": "active", "activeFlags": []}, "turns": [{"id": "turn-1", "status": "inProgress"}, {"id": "turn-2", "status": "inProgress"}]}),
        ] {
            assert_eq!(
                parse_thread_state(&json!({"thread": thread}), &requested),
                Ok(ThreadState::Unproven)
            );
        }
    }

    #[test]
    fn active_response_requires_explicit_active_flags_array() {
        let response = |status: Value| {
            let mut state = TransportState::new();
            state.initialized = true;
            let mut output = Vec::new();
            state
                .read_thread(&mut output, &native("thread-private"))
                .expect("thread read");
            let mut frame = serde_json::to_vec(&json!({
                "id": 2,
                "result": {"thread": {
                    "id": "thread-private",
                    "status": status,
                    "turns": [{"id": "turn-private", "status": "inProgress"}]
                }}
            }))
            .expect("response");
            frame.push(b'\n');
            state.next(&mut Cursor::new(frame), &mut output)
        };

        assert_eq!(
            response(json!({"type": "active"})),
            Ok(Received::ThreadRead(ThreadState::Unproven))
        );
        assert!(matches!(
            response(json!({"type": "active", "activeFlags": []})),
            Ok(Received::ThreadRead(ThreadState::ActiveTurn(_)))
        ));
        assert_eq!(
            response(json!({"type": "active", "activeFlags": null})),
            Ok(Received::ThreadRead(ThreadState::Unproven))
        );
        assert_eq!(
            response(json!({"type": "active", "activeFlags": {}})),
            Err(Error::Malformed)
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

    struct WritesZero;

    impl Write for WritesZero {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Ok(0)
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

        let immediate = write_all_until(&mut FailsImmediately, b"frame", IO_DEADLINE)
            .expect_err("initial error");
        assert_eq!(immediate.receipt, WriteReceipt::ProvenNotWritten);
        assert_eq!(
            failed_write_disposition(immediate),
            NativeWriteDisposition::ProvenNotAccepted
        );

        let initial_zero =
            write_all_until(&mut WritesZero, b"frame", IO_DEADLINE).expect_err("initial zero");
        assert_eq!(initial_zero.receipt, WriteReceipt::ProvenNotWritten);
        assert_eq!(
            failed_write_disposition(initial_zero),
            NativeWriteDisposition::ProvenNotAccepted
        );

        let partial = write_all_until(&mut PartialThenFails(false), b"frame", IO_DEADLINE)
            .expect_err("partial write");
        assert_eq!(partial.receipt, WriteReceipt::PossiblyWritten);
        assert_eq!(
            failed_write_disposition(partial),
            NativeWriteDisposition::Unknown
        );

        let mut state = TransportState::new();
        assert_eq!(state.initialize(&mut FailsImmediately), Err(Error::Closed));
        assert!(!state.ambiguous);

        let mut state = TransportState::new();
        assert_eq!(
            state.initialize(&mut PartialThenFails(false)),
            Err(Error::Ambiguous)
        );
        assert!(state.ambiguous);
        assert!(state.frame.0.is_empty());

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
            "#!/bin/sh\nprintf x > '{}'\nIFS= read -r _ < '{}'\nprintf 'codex-cli 0.152.1\\n'\n",
            ready.display(),
            proceed.display()
        ));
        let replacement = test_executable("#!/bin/sh\nprintf 'codex-cli 0.152.1\\n'\n");
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
            "  printf 'codex-cli 0.152.1\\n'\n",
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
        assert_eq!(thread_ref, native("thread-private"));
        transport
            .start_turn(&thread_ref, "test")
            .expect("turn request");
        assert_eq!(
            transport.receive(),
            Ok(Received::TurnStarted(native("turn-private")))
        );
        assert!(matches!(
            transport.receive(),
            Ok(Received::Notification(Notification::TurnStarted { .. }))
        ));
        assert!(matches!(
            transport.receive(),
            Ok(Received::Notification(Notification::Terminal {
                class: TerminalClass::Succeeded,
                ..
            }))
        ));
        transport.cleanup().expect("cleanup");
        transport.cleanup().expect("idempotent cleanup");
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn composed_transport_qualifies_exact_resume_read_and_reordered_notifications() {
        let executable = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\"}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":3,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}'\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"method\":\"thread/status/changed\",\"params\":{}}'\n",
            "printf '%s\\n' '{\"id\":4,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"active\",\"activeFlags\":[]},\"turns\":[{\"id\":\"turn-old\",\"status\":\"completed\"},{\"id\":\"turn-exact\",\"status\":\"inProgress\"}]}}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let (helper, attachment) = test_tool_attachment();
        let thread = native("thread-private");
        let mut transport = CodexTransport::start(&executable).expect("transport");
        assert_eq!(transport.receive(), Ok(Received::Initialized));
        transport
            .start_attached_thread(&attachment)
            .expect("attached start");
        assert_eq!(
            transport.receive(),
            Ok(Received::ThreadStarted(thread.clone()))
        );
        transport
            .resume_thread(&thread, &attachment)
            .expect("exact resume");
        assert_eq!(
            transport.receive(),
            Ok(Received::ThreadResumed(ThreadState::Idle))
        );
        transport.read_thread(&thread).expect("exact read");
        assert!(matches!(
            transport.receive(),
            Ok(Received::ThreadRead(ThreadState::ActiveTurn(_)))
        ));
        assert_eq!(
            transport.receive(),
            Ok(Received::Notification(Notification::Signal))
        );
        transport.cleanup().expect("cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(executable);
    }

    #[cfg(unix)]
    #[test]
    fn composed_resume_rejects_unrelated_thread_and_unproven_state() {
        let (helper, attachment) = test_tool_attachment();
        let requested = native("thread-private");
        for (response, expected) in [
            (
                "{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-unrelated\",\"status\":{\"type\":\"idle\"},\"turns\":[]}}}",
                Err(Error::Correlation),
            ),
            (
                "{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"active\"},\"turns\":[]}}}",
                Ok(Received::ThreadResumed(ThreadState::Unproven)),
            ),
            (
                "{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-private\",\"status\":{\"type\":\"future\"},\"turns\":[]}}}",
                Ok(Received::ThreadResumed(ThreadState::Unproven)),
            ),
        ] {
            let executable = test_executable(&format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\nIFS= read -r _\nprintf '%s\\n' '{{\"id\":1,\"result\":{{}}}}'\nIFS= read -r _\nIFS= read -r _\nprintf '%s\\n' '{response}'\nwhile IFS= read -r _; do :; done\n"
            ));
            let mut transport = CodexTransport::start(&executable).expect("transport");
            assert_eq!(transport.receive(), Ok(Received::Initialized));
            transport
                .resume_thread(&requested, &attachment)
                .expect("exact resume");
            assert_eq!(transport.receive(), expected);
            transport.cleanup().expect("cleanup");
            let _ = std::fs::remove_file(executable);
        }
        let _ = std::fs::remove_file(helper);
    }

    #[cfg(unix)]
    #[test]
    fn composed_resume_native_error_timeout_and_process_loss_are_typed() {
        let (helper, attachment) = test_tool_attachment();
        let requested = native("thread-private");

        let native_error = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":2,\"error\":{\"code\":-32602,\"message\":\"invalid params\"}}'\n",
            "while IFS= read -r _; do :; done\n"
        ));
        let mut transport = CodexTransport::start(&native_error).expect("native transport");
        assert_eq!(transport.receive(), Ok(Received::Initialized));
        transport
            .resume_thread(&requested, &attachment)
            .expect("resume request");
        assert_eq!(transport.receive(), Err(Error::Native));
        transport.cleanup().expect("native cleanup");
        let _ = std::fs::remove_file(native_error);

        let timeout = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "while :; do sleep 1; done\n"
        ));
        let mut transport = CodexTransport::start(&timeout).expect("timeout transport");
        assert_eq!(transport.receive(), Ok(Received::Initialized));
        transport
            .resume_thread(&requested, &attachment)
            .expect("resume request");
        assert_eq!(
            transport.receive_until(Duration::from_millis(20)),
            Err(Error::Ambiguous)
        );
        transport.cleanup().expect("timeout cleanup");
        let _ = std::fs::remove_file(timeout);

        let process_loss = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "printf '%s\\n' '{\"id\":1,\"result\":{}}'\n",
            "IFS= read -r _\n",
            "IFS= read -r _\n",
            "exit 0\n"
        ));
        let mut transport = CodexTransport::start(&process_loss).expect("loss transport");
        assert_eq!(transport.receive(), Ok(Received::Initialized));
        transport
            .resume_thread(&requested, &attachment)
            .expect("resume request");
        assert_eq!(transport.receive(), Err(Error::Ambiguous));
        transport.cleanup().expect("loss cleanup");
        let _ = std::fs::remove_file(helper);
        let _ = std::fs::remove_file(process_loss);
    }

    #[cfg(unix)]
    #[test]
    fn real_transport_child_exit_matrix_is_no_replay() {
        let before_request = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
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
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
            "IFS= read -r _\n",
            "exit 0\n"
        ));
        let mut transport = CodexTransport::start(&after_write).expect("after-write transport");
        assert_eq!(transport.receive(), Err(Error::Ambiguous));
        transport.cleanup().expect("cleanup after-write exit");
        let _ = std::fs::remove_file(after_write);

        let during_call = test_executable(concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 0.152.1\\n'; exit 0; fi\n",
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
