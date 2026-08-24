//! Length-prefixed JSON frames. Cap size before allocating the payload.

use crate::messages::{WaiterLink, WaiterLinkError, parse_waiter_link, validate};

/// Maximum waiter-link JSON payload (256 KiB).
pub const MAX_FRAME: u32 = 256 * 1024;

/// Frame encode/decode failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// Declared length is zero.
    Empty,
    /// Declared length exceeds [`MAX_FRAME`].
    TooLarge {
        /// Provider-declared length.
        declared: u32,
    },
    /// Buffer shorter than 4-byte prefix plus payload.
    Truncated,
    /// JSON/semantic validation failed.
    Message(WaiterLinkError),
    /// Bytes after the declared payload.
    Trailing,
    /// Payload is not UTF-8.
    InvalidUtf8,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty waiter-link frame"),
            Self::TooLarge { declared } => {
                write!(
                    formatter,
                    "waiter-link frame {declared} exceeds {MAX_FRAME}"
                )
            }
            Self::Truncated => formatter.write_str("truncated waiter-link frame"),
            Self::Message(error) => write!(formatter, "{error}"),
            Self::Trailing => formatter.write_str("trailing bytes after waiter-link frame"),
            Self::InvalidUtf8 => formatter.write_str("waiter-link payload is not utf-8"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode one message: big-endian u32 length then UTF-8 JSON.
///
/// # Errors
///
/// Returns [`FrameError::TooLarge`] if the JSON exceeds [`MAX_FRAME`].
pub fn encode_frame(message: &WaiterLink) -> Result<Vec<u8>, FrameError> {
    validate(message).map_err(FrameError::Message)?;
    let json = serde_json::to_vec(message)
        .map_err(|error| FrameError::Message(WaiterLinkError::Json(error.to_string())))?;
    let len = u32::try_from(json.len()).unwrap_or(u32::MAX);
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge { declared: len });
    }
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Decode one complete frame from a buffer.
///
/// # Errors
///
/// Returns a [`FrameError`] when the prefix is missing, too large, truncated,
/// or the payload fails waiter-link validation.
pub fn decode_frame(bytes: &[u8]) -> Result<WaiterLink, FrameError> {
    let (message, consumed) = decode_prefix(bytes)?;
    if consumed != bytes.len() {
        return Err(FrameError::Trailing);
    }
    Ok(message)
}

/// Decode one frame and report bytes consumed. Allows a stream remainder.
///
/// # Errors
///
/// Same as [`decode_frame`] except trailing bytes are not an error.
pub fn decode_prefix(bytes: &[u8]) -> Result<(WaiterLink, usize), FrameError> {
    if bytes.len() < 4 {
        return Err(FrameError::Truncated);
    }
    let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > MAX_FRAME {
        return Err(FrameError::TooLarge { declared });
    }
    let need = 4 + declared as usize;
    if bytes.len() < need {
        return Err(FrameError::Truncated);
    }
    let json = std::str::from_utf8(&bytes[4..need]).map_err(|_| FrameError::InvalidUtf8)?;
    let message = parse_waiter_link(json).map_err(FrameError::Message)?;
    Ok((message, need))
}
