//! `self wait-on --attach`: block on gearwitd `deliver_events`.
//!
//! Completing this process is `waiter_completed` / `delivery_result`, not
//! `turn_started`. This process does not own Chanvoy.

use std::path::Path;

use gearwit_host::{read_waiter_link, waiter_frame_config, write_waiter_link};
use gearwit_protocol::{SCHEMA, WaiterLink};
use ipcprims::frame::{FrameReader, FrameWriter};
use ipcprims::transport::UnixDomainSocket;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Arguments for an attached waiter session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachSpec {
    /// Arm to attach to.
    pub arm_id: String,
    /// Arm generation.
    pub generation: u64,
    /// Seat token.
    pub seat_id: String,
    /// Attached return route.
    pub route: String,
}

/// Connect, attach, wait for one `deliver_events`, send `return_completed`.
///
/// # Errors
///
/// Returns a short message on connect, protocol, or I/O failure.
pub fn run_attach_session(socket: &Path, spec: &AttachSpec) -> Result<WaiterLink, String> {
    let stream = UnixDomainSocket::connect(socket).map_err(|error| error.to_string())?;
    let writer_stream = stream.try_clone().map_err(|error| error.to_string())?;
    let mut reader = FrameReader::with_config(stream, waiter_frame_config());
    let mut writer = FrameWriter::with_config(writer_stream, waiter_frame_config());
    let request = attach_request(spec);
    write_waiter_link(&mut writer, &request).map_err(|error| error.to_string())?;
    let accepted = read_waiter_link(&mut reader).map_err(|error| error.to_string())?;
    match &accepted {
        WaiterLink::AttachAccepted { .. } => {}
        WaiterLink::AttachRejected { code, .. } => {
            return Err(format!("attach rejected: {code}"));
        }
        _ => return Err("expected attach reply".to_owned()),
    }
    let delivery = read_waiter_link(&mut reader).map_err(|error| error.to_string())?;
    let WaiterLink::DeliverEvents {
        delivery_id,
        link_id,
        signal_id,
        ..
    } = &delivery
    else {
        return Err("expected deliver_events".to_owned());
    };
    let result = WaiterLink::DeliveryResult {
        schema: SCHEMA.to_owned(),
        delivery_id: delivery_id.clone(),
        link_id: link_id.clone(),
        signal_id: signal_id.clone(),
        outcome: "return_completed".to_owned(),
        observed_at: format_time(OffsetDateTime::now_utc()),
    };
    write_waiter_link(&mut writer, &result).map_err(|error| error.to_string())?;
    Ok(delivery)
}

fn attach_request(spec: &AttachSpec) -> WaiterLink {
    WaiterLink::AttachWaiter {
        schema: SCHEMA.to_owned(),
        request_id: ulid::Ulid::new().to_string(),
        waiter_id: ulid::Ulid::new().to_string(),
        arm_id: spec.arm_id.clone(),
        generation: spec.generation,
        seat_id: spec.seat_id.clone(),
        route: spec.route.clone(),
        observed_at: format_time(OffsetDateTime::now_utc()),
    }
}

fn format_time(instant: OffsetDateTime) -> String {
    instant
        .format(&Rfc3339)
        .unwrap_or_else(|_| instant.to_string())
}

/// Print a receipt that does not claim a model turn.
#[must_use]
pub fn render_attach_receipt(delivery: &WaiterLink) -> String {
    match delivery {
        WaiterLink::DeliverEvents {
            delivery_id,
            newest_event_ref,
            events,
            ..
        } => format!(
            "waiter_completed: true\nwait_outcome: matched\nturn_started: unknown\ndelivery_id: {delivery_id}\nnewest_observed: {newest_event_ref}\nevent_count: {}\n",
            events.len()
        ),
        _ => "waiter_completed: true\nwait_outcome: error\nturn_started: unknown\n".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{AttachSpec, render_attach_receipt, run_attach_session};
    use gearwit_host::{
        DeliveryLedger, GearwitPaths, KnownArm, LinkTable, prepare_delivery, read_waiter_link,
        record_delivery_result, send_delivery, serve_attach,
    };
    use gearwit_protocol::ProviderEvent;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use time::OffsetDateTime;

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-01-15T12:05:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("now")
    }

    #[test]
    fn attach_session_returns_delivery_without_turn_claim() {
        let root =
            std::env::temp_dir().join(format!("gearwit-attach-{}-{}", std::process::id(), 1));
        let _ = std::fs::remove_dir_all(&root);
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let instant = now();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let stream = listener.accept().expect("accept");
            let mut table = LinkTable::default();
            let arm = KnownArm {
                arm_id: "01J00000000000000000000010".to_owned(),
                generation: 1,
                seat_id: "example-devrev".to_owned(),
                route: "complete_background_tool".to_owned(),
                coverage_until: instant + time::Duration::minutes(20),
            };
            let mut served = serve_attach(stream, &mut table, instant, &[arm]).expect("attach");
            let link = table.current().expect("link").clone();
            let mut ledger = DeliveryLedger::default();
            let delivery = prepare_delivery(
                &mut ledger,
                &link,
                "01J00000000000000000000021".to_owned(),
                vec![ProviderEvent {
                    provider: "mattermost".to_owned(),
                    event_ref: "post02".to_owned(),
                    actor: None,
                    observed_at: "2026-01-15T12:05:00Z".to_owned(),
                    body: "first bounded event".to_owned(),
                }],
                instant,
            )
            .expect("prepare");
            send_delivery(&mut served.writer, &delivery).expect("send");
            let result = read_waiter_link(&mut served.reader).expect("result");
            record_delivery_result(&mut ledger, &result).expect("record");
            tx.send(!ledger.should_redeliver()).expect("done");
        });
        thread::sleep(Duration::from_millis(20));
        let spec = AttachSpec {
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: "complete_background_tool".to_owned(),
        };
        let delivery = run_attach_session(&socket, &spec).expect("client");
        let receipt = render_attach_receipt(&delivery);
        assert!(receipt.contains("waiter_completed: true"));
        assert!(receipt.contains("turn_started: unknown"));
        assert!(receipt.contains("wait_outcome: matched"));
        assert!(rx.recv_timeout(Duration::from_secs(2)).expect("server"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
