//! One attached return link per `(arm_id, generation)`.

use gearwit_protocol::{SCHEMA, WaiterLink, WaiterLinkError, validate};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// Arm the daemon currently covers.
///
/// Founder v0 expects a single current arm at the daemon boundary. The
/// admission table still keys the live link by `(arm_id, generation)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownArm {
    /// Arm id.
    pub arm_id: String,
    /// Current generation.
    pub generation: u64,
    /// Seat token.
    pub seat_id: String,
    /// Attached route the arm admits.
    pub route: String,
    /// Coverage end.
    pub coverage_until: OffsetDateTime,
}

/// Currently admitted waiter link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedLink {
    /// Matching attach request id.
    pub request_id: String,
    /// Link id.
    pub link_id: String,
    /// Arm id.
    pub arm_id: String,
    /// Generation.
    pub generation: u64,
    /// Waiter id.
    pub waiter_id: String,
    /// Lease end.
    pub lease_until: OffsetDateTime,
}

/// At most one live link.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinkTable {
    current: Option<AdmittedLink>,
    last_accepted: Option<WaiterLink>,
}

impl LinkTable {
    /// Current link, if any.
    #[must_use]
    pub fn current(&self) -> Option<&AdmittedLink> {
        self.current.as_ref()
    }

    /// Drop the link (disconnect). Does not advance handled cursor.
    pub fn drop_current(&mut self) {
        self.current = None;
        self.last_accepted = None;
    }
}

/// Admit or reject an `attach_waiter` message.
///
/// A repeated `request_id` for the active `(arm_id, generation)` returns the
/// cached [`WaiterLink::AttachAccepted`]. A different request while a link is
/// live is `already_attached`.
///
/// # Errors
///
/// Returns [`WaiterLinkError`] if the request is not a valid attach or the
/// constructed reply fails validation.
pub fn admit_attach(
    table: &mut LinkTable,
    request: WaiterLink,
    now: OffsetDateTime,
    arms: &[KnownArm],
) -> Result<WaiterLink, WaiterLinkError> {
    validate(&request)?;
    let WaiterLink::AttachWaiter {
        request_id,
        waiter_id,
        arm_id,
        generation,
        seat_id,
        route,
        ..
    } = request
    else {
        return Err(WaiterLinkError::Semantic("expected attach_waiter"));
    };
    let Some(arm) = arms.iter().find(|arm| arm.arm_id == arm_id) else {
        return reject(&request_id, "unknown_arm", now);
    };
    if arm.generation != generation {
        return reject(&request_id, "stale_generation", now);
    }
    if arm.seat_id != seat_id || arm.route != route {
        return reject(&request_id, "route_mismatch", now);
    }
    if now >= arm.coverage_until {
        return reject(&request_id, "coverage_ended", now);
    }
    if let Some(current) = &table.current {
        if current.request_id == request_id
            && current.arm_id == arm_id
            && current.generation == generation
        {
            return table
                .last_accepted
                .clone()
                .ok_or(WaiterLinkError::Semantic("missing cached admission"));
        }
        return reject(&request_id, "already_attached", now);
    }
    let link_id = ulid::Ulid::new().to_string();
    let lease_until = (now + Duration::minutes(10)).min(arm.coverage_until);
    let accepted = WaiterLink::AttachAccepted {
        schema: SCHEMA.to_owned(),
        request_id: request_id.clone(),
        link_id: link_id.clone(),
        arm_id: arm_id.clone(),
        generation,
        route,
        accepted_at: format_time(now),
        lease_until: format_time(lease_until),
    };
    validate(&accepted)?;
    table.current = Some(AdmittedLink {
        request_id,
        link_id,
        arm_id,
        generation,
        waiter_id,
        lease_until,
    });
    table.last_accepted = Some(accepted.clone());
    Ok(accepted)
}

fn reject(
    request_id: &str,
    code: &'static str,
    now: OffsetDateTime,
) -> Result<WaiterLink, WaiterLinkError> {
    let rejected = WaiterLink::AttachRejected {
        schema: SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
        code: code.to_owned(),
        observed_at: format_time(now),
    };
    validate(&rejected)?;
    Ok(rejected)
}

fn format_time(instant: OffsetDateTime) -> String {
    instant
        .format(&Rfc3339)
        .unwrap_or_else(|_| instant.to_string())
}
