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
    request: WaiterLink,
    last_accepted: WaiterLink,
}

/// Token that may revoke only the link it admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkSession {
    /// Admitted link id.
    pub link_id: String,
}

/// At most one live link.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinkTable {
    current: Option<AdmittedLink>,
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
    }
}

/// Revoke `session` only when it still owns the live link.
pub fn drop_session(table: &mut LinkTable, session: &LinkSession) {
    if table
        .current
        .as_ref()
        .is_some_and(|current| current.link_id == session.link_id)
    {
        table.current = None;
    }
}

/// Drop a live link whose lease has elapsed.
pub fn drop_expired(table: &mut LinkTable, now: OffsetDateTime) {
    if table
        .current
        .as_ref()
        .is_some_and(|current| now >= current.lease_until)
    {
        table.current = None;
    }
}

pub(crate) enum AttachDecision {
    Accept {
        link: Box<AdmittedLink>,
        reply: WaiterLink,
    },
    Replay {
        reply: WaiterLink,
        session: LinkSession,
    },
    Reject {
        reply: WaiterLink,
    },
}

pub(crate) fn commit_attach(table: &mut LinkTable, link: AdmittedLink) {
    table.current = Some(link);
}

pub(crate) fn decide_attach(
    table: &LinkTable,
    request: WaiterLink,
    now: OffsetDateTime,
    arms: &[KnownArm],
) -> Result<AttachDecision, WaiterLinkError> {
    validate(&request)?;
    let WaiterLink::AttachWaiter {
        request_id,
        waiter_id,
        arm_id,
        generation,
        seat_id,
        route,
        ..
    } = &request
    else {
        return Err(WaiterLinkError::Semantic("expected attach_waiter"));
    };
    let Some(arm) = arms.iter().find(|arm| arm.arm_id == *arm_id) else {
        return Ok(AttachDecision::Reject {
            reply: reject_message(request_id, "unknown_arm", now)?,
        });
    };
    if arm.generation != *generation {
        return Ok(AttachDecision::Reject {
            reply: reject_message(request_id, "stale_generation", now)?,
        });
    }
    if arm.seat_id != *seat_id || arm.route != *route {
        return Ok(AttachDecision::Reject {
            reply: reject_message(request_id, "route_mismatch", now)?,
        });
    }
    if now >= arm.coverage_until {
        return Ok(AttachDecision::Reject {
            reply: reject_message(request_id, "coverage_ended", now)?,
        });
    }
    if let Some(current) = &table.current {
        if current.request_id == *request_id {
            if current.request != request {
                return Err(WaiterLinkError::Semantic("request_id conflict"));
            }
            return Ok(AttachDecision::Replay {
                reply: current.last_accepted.clone(),
                session: LinkSession {
                    link_id: current.link_id.clone(),
                },
            });
        }
        return Ok(AttachDecision::Reject {
            reply: reject_message(request_id, "already_attached", now)?,
        });
    }
    let link_id = ulid::Ulid::new().to_string();
    let lease_until = (now + Duration::minutes(10)).min(arm.coverage_until);
    let accepted = WaiterLink::AttachAccepted {
        schema: SCHEMA.to_owned(),
        request_id: request_id.clone(),
        link_id: link_id.clone(),
        arm_id: arm_id.clone(),
        generation: *generation,
        route: route.clone(),
        accepted_at: format_time(now),
        lease_until: format_time(lease_until),
    };
    validate(&accepted)?;
    let session_link = AdmittedLink {
        request_id: request_id.clone(),
        link_id,
        arm_id: arm_id.clone(),
        generation: *generation,
        waiter_id: waiter_id.clone(),
        lease_until,
        request,
        last_accepted: accepted.clone(),
    };
    Ok(AttachDecision::Accept {
        link: Box::new(session_link),
        reply: accepted,
    })
}

/// Admit or reject an `attach_waiter` message.
///
/// A repeated `request_id` with an identical body returns the cached
/// [`WaiterLink::AttachAccepted`]. The same key with a different body is a
/// hard protocol conflict. A different request while a link is live is
/// `already_attached`.
///
/// # Errors
///
/// Returns [`WaiterLinkError`] if the request is not a valid attach, the
/// constructed reply fails validation, or `request_id` is reused with a
/// different body.
pub fn admit_attach(
    table: &mut LinkTable,
    request: WaiterLink,
    now: OffsetDateTime,
    arms: &[KnownArm],
) -> Result<WaiterLink, WaiterLinkError> {
    drop_expired(table, now);
    match decide_attach(table, request, now, arms)? {
        AttachDecision::Accept { link, reply } => {
            commit_attach(table, *link);
            Ok(reply)
        }
        AttachDecision::Replay { reply, .. } | AttachDecision::Reject { reply } => Ok(reply),
    }
}

fn reject_message(
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
