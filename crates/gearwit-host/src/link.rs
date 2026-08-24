//! ipcprims framed waiter-link session (COMMAND channel, 256 KiB).

use std::time::{Duration, Instant};

use gearwit_protocol::{
    HandledCursor, HandledCursorError, Incoming, MAX_PAYLOAD, WaiterLink, WaiterLinkError,
    decode_incoming, decode_payload, encode_handled_payload, encode_payload,
};
use ipcprims::frame::{COMMAND, FrameConfig, FrameError, FrameReader, FrameWriter};
use ipcprims::transport::{IpcStream, TransportError};
use time::OffsetDateTime;

use crate::ack::{AckStore, HandledServe, apply_handled_request};
use crate::admit::{
    AdmittedLink, AttachDecision, KnownArm, LinkSession, LinkTable, commit_attach, decide_attach,
    drop_expired,
};

/// Waiter-link session failure.
#[derive(Debug)]
pub enum LinkError {
    /// Frame layer failed.
    Frame(FrameError),
    /// Payload failed typed validation.
    Payload(gearwit_protocol::PayloadError),
    /// Frame arrived on a channel other than COMMAND.
    WrongChannel(u16),
    /// Semantic attach error.
    Message(WaiterLinkError),
    /// Stream clone or timeout failed.
    Transport(TransportError),
    /// Handled-cursor payload failed typed validation.
    Handled(HandledCursorError),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(error) => write!(formatter, "{error}"),
            Self::Payload(error) => write!(formatter, "{error}"),
            Self::WrongChannel(channel) => {
                write!(
                    formatter,
                    "waiter-link requires COMMAND channel, got {channel}"
                )
            }
            Self::Message(error) => write!(formatter, "{error}"),
            Self::Transport(error) => write!(formatter, "{error}"),
            Self::Handled(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<FrameError> for LinkError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<gearwit_protocol::PayloadError> for LinkError {
    fn from(error: gearwit_protocol::PayloadError) -> Self {
        match error {
            gearwit_protocol::PayloadError::Handled(inner) => Self::Handled(inner),
            other => Self::Payload(other),
        }
    }
}

impl From<HandledCursorError> for LinkError {
    fn from(error: HandledCursorError) -> Self {
        Self::Handled(error)
    }
}

impl From<WaiterLinkError> for LinkError {
    fn from(error: WaiterLinkError) -> Self {
        Self::Message(error)
    }
}

impl From<TransportError> for LinkError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Frame config: 256 KiB cap before payload allocation.
#[must_use]
pub fn waiter_frame_config() -> FrameConfig {
    FrameConfig {
        max_payload_size: MAX_PAYLOAD,
        read_timeout: Some(Duration::from_secs(5)),
        write_timeout: Some(Duration::from_secs(5)),
    }
}

/// Read one waiter-link message from an ipcprims COMMAND frame.
///
/// # Errors
///
/// Returns [`LinkError`] on I/O, oversize, wrong channel, or invalid payload.
pub fn read_waiter_link(reader: &mut FrameReader<IpcStream>) -> Result<WaiterLink, LinkError> {
    let frame = reader.read_frame()?;
    if frame.channel != COMMAND {
        return Err(LinkError::WrongChannel(frame.channel));
    }
    Ok(decode_payload(&frame.payload)?)
}

/// Write one validated waiter-link message as an ipcprims COMMAND frame.
///
/// # Errors
///
/// Returns [`LinkError`] if encode or write fails.
pub fn write_waiter_link(
    writer: &mut FrameWriter<IpcStream>,
    message: &WaiterLink,
) -> Result<(), LinkError> {
    let payload = encode_payload(message)?;
    writer.send(COMMAND, &payload)?;
    Ok(())
}

/// Read one COMMAND frame and dispatch waiter-link vs handled-cursor.
///
/// # Errors
///
/// Returns [`LinkError`] on I/O, oversize, wrong channel, or invalid payload.
pub fn read_incoming(reader: &mut FrameReader<IpcStream>) -> Result<Incoming, LinkError> {
    let frame = reader.read_frame()?;
    if frame.channel != COMMAND {
        return Err(LinkError::WrongChannel(frame.channel));
    }
    Ok(decode_incoming(&frame.payload)?)
}

/// Write one validated handled-cursor message as an ipcprims COMMAND frame.
///
/// # Errors
///
/// Returns [`LinkError`] if encode or write fails.
pub fn write_handled(
    writer: &mut FrameWriter<IpcStream>,
    message: &HandledCursor,
) -> Result<(), LinkError> {
    let payload = encode_handled_payload(message)?;
    writer.send(COMMAND, &payload)?;
    Ok(())
}

/// Outcome of one accepted connection: attach writer or isolated ACK.
pub enum AcceptOutcome {
    /// Waiter-link attach; may occupy the delivery writer.
    Attached(Box<ServeAttach>),
    /// Handled-cursor exchange; never occupies the delivery writer.
    Ack(Box<HandledServe>),
}

/// Outcome of one attach exchange.
pub struct ServeAttach {
    /// Reply written to the waiter.
    pub reply: WaiterLink,
    /// Session token when a live link was admitted or replayed.
    pub session: Option<LinkSession>,
    /// Remaining reader used to observe disconnect and results.
    pub reader: FrameReader<IpcStream>,
    /// Writer used for `deliver_events` on this session.
    pub writer: FrameWriter<IpcStream>,
}

/// Block until the waiter closes the stream.
///
/// # Errors
///
/// Returns [`LinkError`] on I/O other than a clean close, or if another frame
/// arrives.
pub fn wait_disconnect(reader: &mut FrameReader<IpcStream>) -> Result<(), LinkError> {
    match reader.read_frame() {
        Err(FrameError::ConnectionClosed) => Ok(()),
        Err(FrameError::Io(error))
            if error.kind() == std::io::ErrorKind::TimedOut
                || error.kind() == std::io::ErrorKind::WouldBlock =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(LinkError::Message(WaiterLinkError::Semantic(
            "unexpected frame",
        ))),
    }
}

/// Read one attach, write the reply, and commit only after a successful write.
///
/// # Errors
///
/// Returns [`LinkError`] when the session or admission fails. A failed reply
/// write does not leave a new table entry.
pub fn serve_attach(
    stream: IpcStream,
    table: &mut LinkTable,
    now: OffsetDateTime,
    arms: &[KnownArm],
) -> Result<ServeAttach, LinkError> {
    let started = Instant::now();
    let (mut reader, writer) = split_stream(stream)?;
    let request = read_waiter_link(&mut reader)?;
    finish_attach(reader, writer, request, table, now, started, arms)
}

/// Split an accepted stream into a framed reader/writer. Does not touch arm state.
///
/// # Errors
///
/// Returns [`LinkError`] if timeouts cannot be applied or the stream cannot be cloned.
pub fn split_stream(
    stream: IpcStream,
) -> Result<(FrameReader<IpcStream>, FrameWriter<IpcStream>), LinkError> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let writer_stream = stream.try_clone()?;
    Ok((
        FrameReader::with_config(stream, waiter_frame_config()),
        FrameWriter::with_config(writer_stream, waiter_frame_config()),
    ))
}

/// Admission decision ready to write; no socket I/O.
pub struct PreparedAttach {
    reply: WaiterLink,
    session: Option<LinkSession>,
    lease_until: Option<OffsetDateTime>,
    pending: PendingCommit,
    decision_now: OffsetDateTime,
}

enum PendingCommit {
    Accept(Box<AdmittedLink>),
    Reject {
        request: Box<WaiterLink>,
        reply: Box<WaiterLink>,
    },
    Replay,
}

/// Decide attach using only `table`. Caller must not hold `AckStore`.
///
/// # Errors
///
/// Returns [`LinkError`] when the request is not a valid attach.
pub fn prepare_attach(
    table: &mut LinkTable,
    request: WaiterLink,
    now: OffsetDateTime,
    started: Instant,
    arms: &[KnownArm],
) -> Result<PreparedAttach, LinkError> {
    let elapsed = time::Duration::try_from(started.elapsed()).unwrap_or(time::Duration::ZERO);
    let decision_now = now.saturating_add(elapsed);
    drop_expired(table, decision_now);
    Ok(match decide_attach(table, request, decision_now, arms)? {
        AttachDecision::Accept { link, reply } => {
            let session = LinkSession {
                link_id: link.link_id.clone(),
                arm_id: link.arm_id.clone(),
                generation: link.generation,
            };
            let lease_until = Some(link.lease_until);
            PreparedAttach {
                reply,
                session: Some(session),
                lease_until,
                pending: PendingCommit::Accept(link),
                decision_now,
            }
        }
        AttachDecision::Replay { reply, session } => {
            let lease_until = table.current().map(|current| current.lease_until);
            PreparedAttach {
                reply,
                session,
                lease_until,
                pending: PendingCommit::Replay,
                decision_now,
            }
        }
        AttachDecision::Reject { request, reply } => PreparedAttach {
            reply: reply.clone(),
            session: None,
            lease_until: None,
            pending: PendingCommit::Reject {
                request: Box::new(request),
                reply: Box::new(reply),
            },
            decision_now,
        },
    })
}

/// Write the prepared attach reply. Caller must not hold state locks.
///
/// # Errors
///
/// Returns [`LinkError`] if the reply cannot be written.
pub fn write_prepared_attach(
    reader: &mut FrameReader<IpcStream>,
    writer: &mut FrameWriter<IpcStream>,
    prepared: &PreparedAttach,
) -> Result<(), LinkError> {
    if let Some(lease_until) = prepared.lease_until {
        apply_session_read_timeout(reader.get_mut(), lease_until, prepared.decision_now)?;
    }
    write_waiter_link(writer, &prepared.reply)
}

/// Commit a prepared attach after a successful write. Skips a stale generation
/// if a newer live link is already in the table.
pub fn commit_prepared_attach(
    table: &mut LinkTable,
    prepared: PreparedAttach,
    reader: FrameReader<IpcStream>,
    writer: FrameWriter<IpcStream>,
    write_ok: bool,
) -> Option<ServeAttach> {
    if !write_ok {
        return None;
    }
    let PreparedAttach {
        reply,
        session,
        pending,
        ..
    } = prepared;
    match pending {
        PendingCommit::Accept(link) => {
            if table
                .current()
                .is_some_and(|current| current.generation > link.generation)
            {
                return None;
            }
            commit_attach(table, *link);
        }
        PendingCommit::Reject { request, reply } => {
            crate::admit::commit_reject(table, *request, *reply);
        }
        PendingCommit::Replay => {}
    }
    Some(ServeAttach {
        reply,
        session,
        reader,
        writer,
    })
}

/// Record an ACK using only `acks`. Caller writes the reply after dropping the lock.
///
/// # Errors
///
/// Returns [`LinkError`] when the payload is not a request or the recorder fails.
pub fn record_ack(
    acks: &mut AckStore,
    request: HandledCursor,
    now: OffsetDateTime,
) -> Result<HandledServe, LinkError> {
    let HandledCursor::Request { .. } = &request else {
        return Err(LinkError::Handled(HandledCursorError::Semantic(
            "expected request",
        )));
    };
    Ok(apply_handled_request(acks, request, now)?)
}

/// Dispatch waiter-link attach vs handled-cursor on one accepted stream.
///
/// Frame read/write happen outside table/ack mutation. Tests may still pass
/// both stores; they are used one at a time.
///
/// # Errors
///
/// Returns [`LinkError`] on I/O or typed validation failure. Malformed ACK
/// frames do not mutate the link table.
pub fn serve_connection(
    stream: IpcStream,
    table: &mut LinkTable,
    acks: &mut AckStore,
    now: OffsetDateTime,
) -> Result<AcceptOutcome, LinkError> {
    let started = Instant::now();
    let (mut reader, mut writer) = split_stream(stream)?;
    match read_incoming(&mut reader)? {
        Incoming::Waiter(request) => {
            let arms: Vec<KnownArm> = acks.arm().cloned().into_iter().collect();
            let prepared = prepare_attach(table, request, now, started, &arms)?;
            let write_ok = write_prepared_attach(&mut reader, &mut writer, &prepared).is_ok();
            commit_prepared_attach(table, prepared, reader, writer, write_ok)
                .map(|served| AcceptOutcome::Attached(Box::new(served)))
                .ok_or(LinkError::Message(WaiterLinkError::Semantic(
                    "attach write failed",
                )))
        }
        Incoming::Handled(request) => {
            let served = record_ack(acks, request, now)?;
            let _ = write_handled(&mut writer, &served.reply);
            Ok(AcceptOutcome::Ack(Box::new(served)))
        }
    }
}

fn finish_attach(
    mut reader: FrameReader<IpcStream>,
    mut writer: FrameWriter<IpcStream>,
    request: WaiterLink,
    table: &mut LinkTable,
    now: OffsetDateTime,
    started: Instant,
    arms: &[KnownArm],
) -> Result<ServeAttach, LinkError> {
    let prepared = prepare_attach(table, request, now, started, arms)?;
    let write_ok = write_prepared_attach(&mut reader, &mut writer, &prepared).is_ok();
    commit_prepared_attach(table, prepared, reader, writer, write_ok).ok_or(LinkError::Message(
        WaiterLinkError::Semantic("attach write failed"),
    ))
}

fn apply_session_read_timeout(
    stream: &IpcStream,
    lease_until: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), LinkError> {
    stream.set_read_timeout(Some(lease_io_timeout(lease_until, now)))?;
    Ok(())
}

fn lease_io_timeout(lease_until: OffsetDateTime, now: OffsetDateTime) -> Duration {
    if lease_until <= now {
        return Duration::from_millis(1);
    }
    let nanos = (lease_until - now).whole_nanoseconds();
    match u64::try_from(nanos.max(0)) {
        Ok(0) | Err(_) => Duration::from_millis(1),
        Ok(nanos) => Duration::from_nanos(nanos),
    }
}
