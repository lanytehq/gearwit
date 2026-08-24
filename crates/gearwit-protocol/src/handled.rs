//! Handled-cursor acknowledgement. Separate from the waiter-link union.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Wire schema identifier for handled-cursor messages.
pub const HANDLED_SCHEMA: &str = "gearwit.interrupt.handled-cursor.v0";

const REJECT_CODES: &[&str] = &[
    "unknown_arm",
    "stale_generation",
    "seat_mismatch",
    "unknown_signal",
    "ack_before_delivery",
    "cursor_not_member",
    "cursor_beyond_delivered",
    "stale_cursor",
];

/// Typed handled-cursor message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum HandledCursor {
    /// Seat acknowledges a delivered prefix.
    #[serde(rename = "handled_cursor_request")]
    Request {
        /// Schema id.
        schema: String,
        /// Idempotency key.
        request_id: String,
        /// Arm id.
        arm_id: String,
        /// Arm generation.
        generation: u64,
        /// Seat token.
        seat_id: String,
        /// Stable signal id.
        signal_id: String,
        /// Prefix endpoint `event_ref`.
        cursor: String,
        /// Observation time.
        observed_at: String,
    },
    /// Daemon recorded the ACK.
    #[serde(rename = "handled_cursor_accepted")]
    Accepted {
        /// Schema id.
        schema: String,
        /// Matching request.
        request_id: String,
        /// Arm id.
        arm_id: String,
        /// Generation.
        generation: u64,
        /// Signal id.
        signal_id: String,
        /// Recorded cursor.
        cursor: String,
        /// Acceptance time.
        accepted_at: String,
    },
    /// Daemon rejected the ACK.
    #[serde(rename = "handled_cursor_rejected")]
    Rejected {
        /// Schema id.
        schema: String,
        /// Matching request.
        request_id: String,
        /// Reject code.
        code: String,
        /// Observation time.
        observed_at: String,
    },
}

/// Validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandledCursorError {
    /// JSON did not match the tagged union.
    Json(String),
    /// A field failed a pin pattern or semantic rule.
    Semantic(&'static str),
}

impl std::fmt::Display for HandledCursorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "handled-cursor json: {error}"),
            Self::Semantic(error) => write!(formatter, "handled-cursor: {error}"),
        }
    }
}

impl std::error::Error for HandledCursorError {}

/// Parse and validate one handled-cursor JSON object.
///
/// # Errors
///
/// Returns [`HandledCursorError`] on structural or semantic failure.
pub fn parse_handled_cursor(json: &str) -> Result<HandledCursor, HandledCursorError> {
    let message: HandledCursor =
        serde_json::from_str(json).map_err(|error| HandledCursorError::Json(error.to_string()))?;
    validate_handled(&message)?;
    Ok(message)
}

/// Semantically validate an already-deserialized message.
///
/// # Errors
///
/// Returns [`HandledCursorError::Semantic`] when a pin rule fails.
pub fn validate_handled(message: &HandledCursor) -> Result<(), HandledCursorError> {
    match message {
        HandledCursor::Request {
            schema,
            request_id,
            arm_id,
            generation,
            seat_id,
            signal_id,
            cursor,
            observed_at,
        } => {
            schema_ok(schema)?;
            ulid_ok(request_id)?;
            ulid_ok(arm_id)?;
            generation_ok(*generation)?;
            seat_ok(seat_id)?;
            ulid_ok(signal_id)?;
            token_ok(cursor)?;
            time_ok(observed_at)?;
        }
        HandledCursor::Accepted {
            schema,
            request_id,
            arm_id,
            generation,
            signal_id,
            cursor,
            accepted_at,
        } => {
            schema_ok(schema)?;
            ulid_ok(request_id)?;
            ulid_ok(arm_id)?;
            generation_ok(*generation)?;
            ulid_ok(signal_id)?;
            token_ok(cursor)?;
            time_ok(accepted_at)?;
        }
        HandledCursor::Rejected {
            schema,
            request_id,
            code,
            observed_at,
        } => {
            schema_ok(schema)?;
            ulid_ok(request_id)?;
            if !REJECT_CODES.contains(&code.as_str()) {
                return Err(HandledCursorError::Semantic("unknown reject code"));
            }
            time_ok(observed_at)?;
        }
    }
    Ok(())
}

fn schema_ok(schema: &str) -> Result<(), HandledCursorError> {
    if schema == HANDLED_SCHEMA {
        Ok(())
    } else {
        Err(HandledCursorError::Semantic("schema id"))
    }
}

fn ulid_ok(value: &str) -> Result<(), HandledCursorError> {
    let bytes = value.as_bytes();
    if bytes.len() == 26
        && bytes.iter().all(|byte| {
            byte.is_ascii_uppercase() && !b"ILOU".contains(byte) || byte.is_ascii_digit()
        })
    {
        Ok(())
    } else {
        Err(HandledCursorError::Semantic("ulid"))
    }
}

fn generation_ok(generation: u64) -> Result<(), HandledCursorError> {
    if generation >= 1 {
        Ok(())
    } else {
        Err(HandledCursorError::Semantic("generation"))
    }
}

fn seat_ok(seat: &str) -> Result<(), HandledCursorError> {
    let bytes = seat.as_bytes();
    if (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        Ok(())
    } else {
        Err(HandledCursorError::Semantic("seat_id"))
    }
}

fn token_ok(value: &str) -> Result<(), HandledCursorError> {
    if (1..=256).contains(&value.chars().count())
        && !value.chars().any(|ch| ch <= '\u{001F}' || ch == '\u{007F}')
    {
        Ok(())
    } else {
        Err(HandledCursorError::Semantic("token"))
    }
}

fn time_ok(value: &str) -> Result<OffsetDateTime, HandledCursorError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| HandledCursorError::Semantic("timestamp"))
}
