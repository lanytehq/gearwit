//! Validated waiter-link JSON payloads. Wire framing is ipcprims, not this crate.

use crate::messages::{WaiterLink, WaiterLinkError, parse_waiter_link, validate};

/// Maximum waiter-link JSON payload (256 KiB).
pub const MAX_PAYLOAD: usize = 256 * 1024;

/// Payload encode/decode failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadError {
    /// Serialized JSON is empty.
    Empty,
    /// Payload exceeds [`MAX_PAYLOAD`].
    TooLarge {
        /// Observed byte length.
        size: usize,
    },
    /// JSON/semantic validation failed.
    Message(WaiterLinkError),
    /// Payload is not UTF-8.
    InvalidUtf8,
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty waiter-link payload"),
            Self::TooLarge { size } => {
                write!(
                    formatter,
                    "waiter-link payload {size} exceeds {MAX_PAYLOAD}"
                )
            }
            Self::Message(error) => write!(formatter, "{error}"),
            Self::InvalidUtf8 => formatter.write_str("waiter-link payload is not utf-8"),
        }
    }
}

impl std::error::Error for PayloadError {}

/// Serialize one validated waiter-link message to JSON bytes.
///
/// # Errors
///
/// Returns [`PayloadError::TooLarge`] if the JSON exceeds [`MAX_PAYLOAD`].
pub fn encode_payload(message: &WaiterLink) -> Result<Vec<u8>, PayloadError> {
    validate(message).map_err(PayloadError::Message)?;
    let json = serde_json::to_vec(message)
        .map_err(|error| PayloadError::Message(WaiterLinkError::Json(error.to_string())))?;
    if json.is_empty() {
        return Err(PayloadError::Empty);
    }
    if json.len() > MAX_PAYLOAD {
        return Err(PayloadError::TooLarge { size: json.len() });
    }
    Ok(json)
}

/// Parse one waiter-link payload from JSON bytes.
///
/// # Errors
///
/// Returns a [`PayloadError`] when the bytes are empty, too large, not UTF-8,
/// or fail waiter-link validation.
pub fn decode_payload(bytes: &[u8]) -> Result<WaiterLink, PayloadError> {
    if bytes.is_empty() {
        return Err(PayloadError::Empty);
    }
    if bytes.len() > MAX_PAYLOAD {
        return Err(PayloadError::TooLarge { size: bytes.len() });
    }
    let json = std::str::from_utf8(bytes).map_err(|_| PayloadError::InvalidUtf8)?;
    parse_waiter_link(json).map_err(PayloadError::Message)
}
