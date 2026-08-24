//! Stable `deliver_events` batches and `delivery_result` handling.

use gearwit_protocol::{ProviderEvent, SCHEMA, WaiterLink, WaiterLinkError, validate};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::admit::AdmittedLink;
use crate::link::{LinkError, write_waiter_link};
use ipcprims::frame::FrameWriter;
use ipcprims::transport::IpcStream;

/// In-memory pending delivery. A.3 does not open a database.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeliveryLedger {
    pending: Option<PendingDelivery>,
}

/// One undelivered or unacked batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDelivery {
    /// Stable delivery id.
    pub delivery_id: String,
    /// Link that last attempted the batch.
    pub link_id: String,
    /// Deliver payload to (re)send.
    pub message: WaiterLink,
    /// Terminal waiter outcome, if any.
    pub result: Option<String>,
}

impl DeliveryLedger {
    /// Current pending delivery.
    #[must_use]
    pub fn pending(&self) -> Option<&PendingDelivery> {
        self.pending.as_ref()
    }

    /// Whether the same `delivery_id` should be sent again.
    #[must_use]
    pub fn should_redeliver(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.result.is_none())
    }
}

/// Build a new validated `deliver_events` batch.
///
/// Fails if a non-terminal delivery is already pending. Route is taken from
/// the admitted link, not the caller.
///
/// # Errors
///
/// Returns [`WaiterLinkError`] if a delivery is pending or validation fails.
pub fn prepare_delivery(
    ledger: &mut DeliveryLedger,
    link: &AdmittedLink,
    signal_id: String,
    events: Vec<ProviderEvent>,
    now: OffsetDateTime,
) -> Result<WaiterLink, WaiterLinkError> {
    if ledger
        .pending
        .as_ref()
        .is_some_and(|pending| pending.result.is_none())
    {
        return Err(WaiterLinkError::Semantic("delivery pending"));
    }
    let newest = events
        .last()
        .map(|event| event.event_ref.clone())
        .ok_or(WaiterLinkError::Semantic("empty delivery"))?;
    let message = WaiterLink::DeliverEvents {
        schema: SCHEMA.to_owned(),
        delivery_id: ulid::Ulid::new().to_string(),
        link_id: link.link_id.clone(),
        arm_id: link.arm_id.clone(),
        generation: link.generation,
        signal_id,
        route: link.route.clone(),
        events,
        newest_event_ref: newest,
        attempted_at: format_time(now),
    };
    validate(&message)?;
    let delivery_id = match &message {
        WaiterLink::DeliverEvents { delivery_id, .. } => delivery_id.clone(),
        _ => return Err(WaiterLinkError::Semantic("expected deliver_events")),
    };
    ledger.pending = Some(PendingDelivery {
        delivery_id,
        link_id: link.link_id.clone(),
        message: message.clone(),
        result: None,
    });
    Ok(message)
}

/// Resend the pending batch on a successor link.
///
/// Updates `link_id` and `attempted_at` only. Arm, generation, signal, route,
/// and events must still match the successor link's authority.
///
/// # Errors
///
/// Returns [`WaiterLinkError`] if there is nothing to redeliver or the
/// successor does not match the original authority.
pub fn redeliver_pending(
    ledger: &mut DeliveryLedger,
    link: &AdmittedLink,
    now: OffsetDateTime,
) -> Result<WaiterLink, WaiterLinkError> {
    let Some(pending) = ledger.pending.as_mut() else {
        return Err(WaiterLinkError::Semantic("no pending delivery"));
    };
    if pending.result.is_some() {
        return Err(WaiterLinkError::Semantic("delivery already terminal"));
    }
    let WaiterLink::DeliverEvents {
        arm_id,
        generation,
        route,
        link_id: stored_link,
        attempted_at,
        ..
    } = &mut pending.message
    else {
        return Err(WaiterLinkError::Semantic("expected deliver_events"));
    };
    if *arm_id != link.arm_id || *generation != link.generation || *route != link.route {
        return Err(WaiterLinkError::Semantic("successor authority mismatch"));
    }
    link.link_id.clone_into(stored_link);
    *attempted_at = format_time(now);
    validate(&pending.message)?;
    link.link_id.clone_into(&mut pending.link_id);
    Ok(pending.message.clone())
}

/// Write one `deliver_events` frame. Does not record `turn_started`.
///
/// # Errors
///
/// Returns [`LinkError`] if the message is not `deliver_events` or write fails.
pub fn send_delivery(
    writer: &mut FrameWriter<IpcStream>,
    message: &WaiterLink,
) -> Result<(), LinkError> {
    if !matches!(message, WaiterLink::DeliverEvents { .. }) {
        return Err(LinkError::Message(WaiterLinkError::Semantic(
            "expected deliver_events",
        )));
    }
    write_waiter_link(writer, message)
}

/// Record a waiter `delivery_result` against the current attempt.
///
/// Requires `delivery_id`, current attempt `link_id`, and `signal_id`.
/// Terminal outcomes are monotonic: exact replay is idempotent; a different
/// outcome is a hard error; `link_lost` cannot follow a terminal result.
///
/// # Errors
///
/// Returns [`WaiterLinkError`] on type, correlation, or transition failure.
pub fn record_delivery_result(
    ledger: &mut DeliveryLedger,
    result: &WaiterLink,
) -> Result<(), WaiterLinkError> {
    validate(result)?;
    let WaiterLink::DeliveryResult {
        delivery_id,
        link_id,
        signal_id,
        outcome,
        ..
    } = result
    else {
        return Err(WaiterLinkError::Semantic("expected delivery_result"));
    };
    let Some(pending) = ledger.pending.as_mut() else {
        return Err(WaiterLinkError::Semantic("no pending delivery"));
    };
    let WaiterLink::DeliverEvents {
        signal_id: pending_signal,
        ..
    } = &pending.message
    else {
        return Err(WaiterLinkError::Semantic("expected deliver_events"));
    };
    if pending.delivery_id != *delivery_id {
        return Err(WaiterLinkError::Semantic("delivery_id mismatch"));
    }
    if pending.link_id != *link_id {
        return Err(WaiterLinkError::Semantic("link_id mismatch"));
    }
    if pending_signal != signal_id {
        return Err(WaiterLinkError::Semantic("signal_id mismatch"));
    }
    if let Some(existing) = &pending.result {
        if existing == outcome {
            return Ok(());
        }
        return Err(WaiterLinkError::Semantic("conflicting delivery outcome"));
    }
    if outcome == "link_lost" {
        return Ok(());
    }
    pending.result = Some(outcome.clone());
    Ok(())
}

fn format_time(instant: OffsetDateTime) -> String {
    instant
        .format(&Rfc3339)
        .unwrap_or_else(|_| instant.to_string())
}
