//! ipcprims framed waiter-link session (COMMAND channel, 256 KiB).

use std::time::Duration;

use gearwit_protocol::{MAX_PAYLOAD, WaiterLink, WaiterLinkError, decode_payload, encode_payload};
use ipcprims::frame::{COMMAND, FrameConfig, FrameError, FrameReader, FrameWriter};
use ipcprims::transport::{IpcStream, TransportError};
use time::OffsetDateTime;

use crate::admit::{KnownArm, LinkTable, admit_attach};

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
        ..FrameConfig::default()
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

/// Read one attach, admit, and write the reply on the same stream.
///
/// # Errors
///
/// Returns [`LinkError`] when the session or admission fails.
pub fn serve_attach(
    stream: IpcStream,
    table: &mut LinkTable,
    now: OffsetDateTime,
    arms: &[KnownArm],
) -> Result<WaiterLink, LinkError> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let writer_stream = stream.try_clone()?;
    let mut reader = FrameReader::with_config(stream, waiter_frame_config());
    let mut writer = FrameWriter::with_config(writer_stream, waiter_frame_config());
    let request = read_waiter_link(&mut reader)?;
    let reply = admit_attach(table, request, now, arms)?;
    write_waiter_link(&mut writer, &reply)?;
    Ok(reply)
}
