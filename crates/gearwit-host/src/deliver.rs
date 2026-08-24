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
        self.pending.as_ref().is_some_and(|pending| {
            pending.result.as_deref() != Some("return_completed")
                && pending.result.as_deref() != Some("return_failed")
        })
    }
}

/// Build a validated `deliver_events` message and store it as pending.
///
/// # Errors
///
/// Returns [`WaiterLinkError`] if the constructed message fails validation.
pub fn prepare_delivery(
    ledger: &mut DeliveryLedger,
    link: &AdmittedLink,
    signal_id: String,
    route: String,
    events: Vec<ProviderEvent>,
    now: OffsetDateTime,
) -> Result<WaiterLink, WaiterLinkError> {
    if let Some(pending) = &ledger.pending
        && pending.result.as_deref() != Some("return_completed")
        && pending.result.as_deref() != Some("return_failed")
    {
        return retarget_pending(ledger, &link.link_id);
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
        route,
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

fn retarget_pending(
    ledger: &mut DeliveryLedger,
    link_id: &str,
) -> Result<WaiterLink, WaiterLinkError> {
    let Some(pending) = ledger.pending.as_mut() else {
        return Err(WaiterLinkError::Semantic("no pending delivery"));
    };
    if let WaiterLink::DeliverEvents {
        link_id: stored_link,
        ..
    } = &mut pending.message
    {
        link_id.clone_into(stored_link);
    }
    link_id.clone_into(&mut pending.link_id);
    Ok(pending.message.clone())
}

/// Write `deliver_events`. Does not record `turn_started`.
///
/// # Errors
///
/// Returns [`LinkError`] if the frame cannot be written.
pub fn send_delivery(
    writer: &mut FrameWriter<IpcStream>,
    message: &WaiterLink,
) -> Result<(), LinkError> {
    write_waiter_link(writer, message)
}

/// Record a waiter `delivery_result`. Same `delivery_id` only.
///
/// # Errors
///
/// Returns [`WaiterLinkError`] on type or id mismatch.
pub fn record_delivery_result(
    ledger: &mut DeliveryLedger,
    result: &WaiterLink,
) -> Result<(), WaiterLinkError> {
    validate(result)?;
    let WaiterLink::DeliveryResult {
        delivery_id,
        outcome,
        ..
    } = result
    else {
        return Err(WaiterLinkError::Semantic("expected delivery_result"));
    };
    let Some(pending) = ledger.pending.as_mut() else {
        return Err(WaiterLinkError::Semantic("no pending delivery"));
    };
    if pending.delivery_id != *delivery_id {
        return Err(WaiterLinkError::Semantic("delivery_id mismatch"));
    }
    if outcome == "link_lost" {
        pending.result = None;
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
