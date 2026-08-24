//! ipcprims framed waiter-link session (COMMAND channel, 256 KiB).

use std::time::{Duration, Instant};

use gearwit_protocol::{MAX_PAYLOAD, WaiterLink, WaiterLinkError, decode_payload, encode_payload};
use ipcprims::frame::{COMMAND, FrameConfig, FrameError, FrameReader, FrameWriter};
use ipcprims::transport::{IpcStream, TransportError};
use time::OffsetDateTime;

use crate::admit::{
    AttachDecision, KnownArm, LinkSession, LinkTable, commit_attach, decide_attach, drop_expired,
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
        Self::Payload(error)
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
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let writer_stream = stream.try_clone()?;
    let mut reader = FrameReader::with_config(stream, waiter_frame_config());
    let mut writer = FrameWriter::with_config(writer_stream, waiter_frame_config());
    let request = read_waiter_link(&mut reader)?;
    let elapsed = time::Duration::try_from(started.elapsed()).unwrap_or(time::Duration::ZERO);
    let decision_now = now.saturating_add(elapsed);
    drop_expired(table, decision_now);
    let (reply, session) = match decide_attach(table, request, decision_now, arms)? {
        AttachDecision::Accept { link, reply } => {
            let session = LinkSession {
                link_id: link.link_id.clone(),
                arm_id: link.arm_id.clone(),
                generation: link.generation,
            };
            apply_session_read_timeout(reader.get_mut(), link.lease_until, decision_now)?;
            write_waiter_link(&mut writer, &reply)?;
            commit_attach(table, *link);
            (reply, Some(session))
        }
        AttachDecision::Replay { reply, session } => {
            if let Some(current) = table.current() {
                apply_session_read_timeout(reader.get_mut(), current.lease_until, decision_now)?;
            }
            write_waiter_link(&mut writer, &reply)?;
            (reply, session)
        }
        AttachDecision::Reject { request, reply } => {
            write_waiter_link(&mut writer, &reply)?;
            crate::admit::commit_reject(table, request, reply.clone());
            (reply, None)
        }
    };
    Ok(ServeAttach {
        reply,
        session,
        reader,
        writer,
    })
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
