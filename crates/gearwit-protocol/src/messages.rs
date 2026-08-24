//! Strict waiter-link types. Serde plus semantic checks; no JSON Schema runtime.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Crucible commit this crate conforms to.
pub const PIN_COMMIT: &str = "d12164211358e25c33048b8804c0bf60429437e5";
/// Wire schema identifier.
pub const SCHEMA: &str = "gearwit.interrupt.waiter-link.v0";

/// Typed waiter-link message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum WaiterLink {
    /// Waiter asks to attach to an arm.
    #[serde(rename = "attach_waiter")]
    AttachWaiter {
        /// Schema id.
        schema: String,
        /// Idempotency key.
        request_id: String,
        /// Waiter instance id.
        waiter_id: String,
        /// Arm being attached.
        arm_id: String,
        /// Arm generation.
        generation: u32,
        /// Seat token.
        seat_id: String,
        /// Attached return route.
        route: String,
        /// Observation time.
        observed_at: String,
    },
    /// Daemon admitted the link.
    #[serde(rename = "attach_accepted")]
    AttachAccepted {
        /// Schema id.
        schema: String,
        /// Matching request.
        request_id: String,
        /// Link id.
        link_id: String,
        /// Arm id.
        arm_id: String,
        /// Arm generation.
        generation: u32,
        /// Admitted route.
        route: String,
        /// Admission time.
        accepted_at: String,
        /// Lease expiry.
        lease_until: String,
    },
    /// Daemon refused the link.
    #[serde(rename = "attach_rejected")]
    AttachRejected {
        /// Schema id.
        schema: String,
        /// Matching request.
        request_id: String,
        /// Rejection code.
        code: String,
        /// Observation time.
        observed_at: String,
    },
    /// Daemon delivers a stable event batch.
    #[serde(rename = "deliver_events")]
    DeliverEvents {
        /// Schema id.
        schema: String,
        /// Stable delivery id.
        delivery_id: String,
        /// Link id.
        link_id: String,
        /// Arm id.
        arm_id: String,
        /// Arm generation.
        generation: u32,
        /// Signal id.
        signal_id: String,
        /// Route.
        route: String,
        /// Oldest-first events.
        events: Vec<ProviderEvent>,
        /// Must equal the last `event_ref`.
        newest_event_ref: String,
        /// Attempt time.
        attempted_at: String,
    },
    /// Waiter reports return-path outcome.
    #[serde(rename = "delivery_result")]
    DeliveryResult {
        /// Schema id.
        schema: String,
        /// Delivery id.
        delivery_id: String,
        /// Link id.
        link_id: String,
        /// Signal id.
        signal_id: String,
        /// Outcome token.
        outcome: String,
        /// Observation time.
        observed_at: String,
    },
}

/// One untrusted provider event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEvent {
    /// Provider name.
    pub provider: String,
    /// Opaque event ref.
    pub event_ref: String,
    /// Optional actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Observation time.
    pub observed_at: String,
    /// Bounded body.
    pub body: String,
}

/// Validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaiterLinkError {
    /// JSON did not match the tagged union.
    Json(String),
    /// A field failed a pin pattern or semantic rule.
    Semantic(&'static str),
}

impl std::fmt::Display for WaiterLinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "waiter-link json: {error}"),
            Self::Semantic(error) => write!(formatter, "waiter-link: {error}"),
        }
    }
}

impl std::error::Error for WaiterLinkError {}

/// Parse and semantically validate one waiter-link JSON object.
///
/// # Errors
///
/// Returns [`WaiterLinkError`] on structural or semantic failure.
pub fn parse_waiter_link(json: &str) -> Result<WaiterLink, WaiterLinkError> {
    let message: WaiterLink =
        serde_json::from_str(json).map_err(|error| WaiterLinkError::Json(error.to_string()))?;
    validate(&message)?;
    Ok(message)
}

fn validate(message: &WaiterLink) -> Result<(), WaiterLinkError> {
    match message {
        WaiterLink::AttachWaiter {
            schema,
            request_id,
            waiter_id,
            arm_id,
            generation,
            seat_id,
            route,
            observed_at,
        } => {
            schema_ok(schema)?;
            ulid_ok(request_id)?;
            ulid_ok(waiter_id)?;
            ulid_ok(arm_id)?;
            generation_ok(*generation)?;
            seat_ok(seat_id)?;
            attached_route_ok(route)?;
            time_ok(observed_at)?;
        }
        WaiterLink::AttachAccepted {
            schema,
            request_id,
            link_id,
            arm_id,
            generation,
            route,
            accepted_at,
            lease_until,
        } => {
            schema_ok(schema)?;
            ulid_ok(request_id)?;
            ulid_ok(link_id)?;
            ulid_ok(arm_id)?;
            generation_ok(*generation)?;
            attached_route_ok(route)?;
            let accepted = time_ok(accepted_at)?;
            let lease = time_ok(lease_until)?;
            if lease <= accepted {
                return Err(WaiterLinkError::Semantic(
                    "lease_until must be after accepted_at",
                ));
            }
        }
        WaiterLink::AttachRejected {
            schema,
            request_id,
            code,
            observed_at,
        } => {
            schema_ok(schema)?;
            ulid_ok(request_id)?;
            reject_code_ok(code)?;
            time_ok(observed_at)?;
        }
        WaiterLink::DeliverEvents {
            schema,
            delivery_id,
            link_id,
            arm_id,
            generation,
            signal_id,
            route,
            events,
            newest_event_ref,
            attempted_at,
        } => {
            schema_ok(schema)?;
            ulid_ok(delivery_id)?;
            ulid_ok(link_id)?;
            ulid_ok(arm_id)?;
            generation_ok(*generation)?;
            ulid_ok(signal_id)?;
            attached_route_ok(route)?;
            time_ok(attempted_at)?;
            validate_events(events, newest_event_ref)?;
        }
        WaiterLink::DeliveryResult {
            schema,
            delivery_id,
            link_id,
            signal_id,
            outcome,
            observed_at,
        } => {
            schema_ok(schema)?;
            ulid_ok(delivery_id)?;
            ulid_ok(link_id)?;
            ulid_ok(signal_id)?;
            outcome_ok(outcome)?;
            time_ok(observed_at)?;
        }
    }
    Ok(())
}

fn validate_events(events: &[ProviderEvent], newest: &str) -> Result<(), WaiterLinkError> {
    if events.is_empty() || events.len() > 64 {
        return Err(WaiterLinkError::Semantic(
            "events must contain 1..=64 items",
        ));
    }
    let mut seen = BTreeSet::new();
    for event in events {
        token_ok(&event.provider)?;
        token_ok(&event.event_ref)?;
        if let Some(actor) = &event.actor {
            token_ok(actor)?;
        }
        time_ok(&event.observed_at)?;
        body_ok(&event.body)?;
        if !seen.insert(event.event_ref.as_str()) {
            return Err(WaiterLinkError::Semantic("duplicate event_ref"));
        }
    }
    token_ok(newest)?;
    let last = events.last().map(|event| event.event_ref.as_str());
    if last != Some(newest) {
        return Err(WaiterLinkError::Semantic(
            "newest_event_ref must be last event_ref",
        ));
    }
    Ok(())
}

fn schema_ok(schema: &str) -> Result<(), WaiterLinkError> {
    if schema == SCHEMA {
        Ok(())
    } else {
        Err(WaiterLinkError::Semantic("unknown schema"))
    }
}

fn ulid_ok(value: &str) -> Result<(), WaiterLinkError> {
    if value.len() == 26
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'
            )
        })
    {
        Ok(())
    } else {
        Err(WaiterLinkError::Semantic("invalid ulid"))
    }
}

fn generation_ok(generation: u32) -> Result<(), WaiterLinkError> {
    if generation >= 1 {
        Ok(())
    } else {
        Err(WaiterLinkError::Semantic("generation must be >= 1"))
    }
}

fn seat_ok(seat: &str) -> Result<(), WaiterLinkError> {
    let bytes = seat.as_bytes();
    if (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        Ok(())
    } else {
        Err(WaiterLinkError::Semantic("invalid seat_id"))
    }
}

fn attached_route_ok(route: &str) -> Result<(), WaiterLinkError> {
    if matches!(route, "return_foreground" | "complete_background_tool") {
        Ok(())
    } else {
        Err(WaiterLinkError::Semantic("route is not an attached return"))
    }
}

fn reject_code_ok(code: &str) -> Result<(), WaiterLinkError> {
    if matches!(
        code,
        "unknown_arm"
            | "stale_generation"
            | "route_mismatch"
            | "already_attached"
            | "coverage_ended"
    ) {
        Ok(())
    } else {
        Err(WaiterLinkError::Semantic("unknown reject code"))
    }
}

fn outcome_ok(outcome: &str) -> Result<(), WaiterLinkError> {
    if matches!(outcome, "return_completed" | "return_failed" | "link_lost") {
        Ok(())
    } else {
        Err(WaiterLinkError::Semantic("unknown delivery outcome"))
    }
}

fn token_ok(value: &str) -> Result<(), WaiterLinkError> {
    if (1..=256).contains(&value.len())
        && value
            .chars()
            .all(|character| character > '\u{0020}' && character != '\u{007F}')
    {
        Ok(())
    } else {
        Err(WaiterLinkError::Semantic("invalid safe token"))
    }
}

fn body_ok(value: &str) -> Result<(), WaiterLinkError> {
    if value.len() > 4096 {
        return Err(WaiterLinkError::Semantic("body too long"));
    }
    if value.chars().any(|character| {
        let code = character as u32;
        (0x00..=0x08).contains(&code)
            || code == 0x0B
            || code == 0x0C
            || (0x0E..=0x1F).contains(&code)
            || (0x7F..=0x9F).contains(&code)
    }) {
        return Err(WaiterLinkError::Semantic(
            "body contains forbidden controls",
        ));
    }
    Ok(())
}

fn time_ok(value: &str) -> Result<OffsetDateTime, WaiterLinkError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| WaiterLinkError::Semantic("invalid date-time"))
}
