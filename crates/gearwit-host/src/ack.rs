//! Handled-cursor acknowledgement. Separate from waiter-link attach.

use std::collections::BTreeMap;

use crate::admit::KnownArm;
use gearwit_protocol::{HANDLED_SCHEMA, HandledCursor, HandledCursorError, validate_handled};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// In-memory ACK authority for one daemon arm.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AckStore {
    arm: Option<KnownArm>,
    signals: BTreeMap<String, SignalBatch>,
    history: BTreeMap<String, HistoryEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HistoryEntry {
    request: HandledCursor,
    reply: HandledCursor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignalBatch {
    delivered: Vec<String>,
    after_bound: Vec<String>,
    handled: Option<String>,
    closed: bool,
}

impl AckStore {
    /// Bind the live arm.
    #[must_use]
    pub fn with_arm(arm: KnownArm) -> Self {
        Self {
            arm: Some(arm),
            signals: BTreeMap::new(),
            history: BTreeMap::new(),
        }
    }

    /// Record a delivered batch for `signal_id`.
    pub fn note_delivered(
        &mut self,
        signal_id: String,
        delivered: Vec<String>,
        drain_snapshot: Vec<String>,
    ) {
        let newest = delivered.last().cloned();
        let after_bound = newest
            .as_ref()
            .map(|bound| {
                drain_snapshot
                    .into_iter()
                    .skip_while(|event_ref| event_ref != bound)
                    .skip(1)
                    .collect()
            })
            .unwrap_or_default();
        self.signals.insert(
            signal_id,
            SignalBatch {
                delivered,
                after_bound,
                handled: None,
                closed: false,
            },
        );
    }

    /// Live arm, if any.
    #[must_use]
    pub fn arm(&self) -> Option<&KnownArm> {
        self.arm.as_ref()
    }
}

/// Record an ACK. Does not re-arm.
///
/// # Errors
///
/// Returns [`HandledCursorError`] when the request is not a valid ACK request.
pub fn record_handled(
    store: &mut AckStore,
    request: HandledCursor,
    now: OffsetDateTime,
) -> Result<HandledCursor, HandledCursorError> {
    validate_handled(&request)?;
    let HandledCursor::Request { request_id, .. } = &request else {
        return Err(HandledCursorError::Semantic("expected request"));
    };

    if let Some(existing) = store.history.get(request_id) {
        if existing.request == request {
            return Ok(existing.reply.clone());
        }
        return Err(HandledCursorError::Semantic("request_id conflict"));
    }

    let reply = decide(store, &request, now);
    store.history.insert(
        request_id.clone(),
        HistoryEntry {
            request,
            reply: reply.clone(),
        },
    );
    Ok(reply)
}

/// Close the signal at the last recorded cursor and bump generation.
///
/// # Errors
///
/// Fails if nothing has been recorded or the signal is already closed.
pub fn rearm_from_handled(
    store: &mut AckStore,
    signal_id: &str,
) -> Result<String, HandledCursorError> {
    let Some(arm) = store.arm.as_mut() else {
        return Err(HandledCursorError::Semantic("unknown_arm"));
    };
    let Some(batch) = store.signals.get_mut(signal_id) else {
        return Err(HandledCursorError::Semantic("unknown_signal"));
    };
    let Some(cursor) = batch.handled.clone() else {
        return Err(HandledCursorError::Semantic("ack_before_delivery"));
    };
    if batch.closed {
        return Err(HandledCursorError::Semantic("stale_generation"));
    }
    batch.closed = true;
    arm.generation = arm.generation.saturating_add(1);
    Ok(cursor)
}

fn decide(store: &mut AckStore, request: &HandledCursor, now: OffsetDateTime) -> HandledCursor {
    let HandledCursor::Request {
        request_id,
        arm_id,
        generation,
        seat_id,
        signal_id,
        cursor,
        ..
    } = request
    else {
        return HandledCursor::Rejected {
            schema: HANDLED_SCHEMA.to_owned(),
            request_id: "01J00000000000000000000000".to_owned(),
            code: "unknown_arm".to_owned(),
            observed_at: format_time(now),
        };
    };
    let rejected = |code: &str| HandledCursor::Rejected {
        schema: HANDLED_SCHEMA.to_owned(),
        request_id: request_id.clone(),
        code: code.to_owned(),
        observed_at: format_time(now),
    };
    let Some(arm) = store.arm.as_ref() else {
        return rejected("unknown_arm");
    };
    if &arm.arm_id != arm_id {
        return rejected("unknown_arm");
    }
    if &arm.seat_id != seat_id {
        return rejected("seat_mismatch");
    }
    if *generation != arm.generation {
        return rejected("stale_generation");
    }
    let Some(batch) = store.signals.get_mut(signal_id) else {
        return rejected("unknown_signal");
    };
    if batch.closed {
        return rejected("stale_generation");
    }
    if batch.delivered.is_empty() {
        return rejected("ack_before_delivery");
    }
    if batch
        .after_bound
        .iter()
        .any(|event_ref| event_ref == cursor)
    {
        return rejected("cursor_beyond_delivered");
    }
    let position = batch
        .delivered
        .iter()
        .position(|event_ref| event_ref == cursor);
    let Some(position) = position else {
        return rejected("cursor_not_member");
    };
    if let Some(handled) = &batch.handled {
        let handled_at = batch
            .delivered
            .iter()
            .position(|event_ref| event_ref == handled);
        if handled_at.is_some_and(|index| position < index) {
            return rejected("stale_cursor");
        }
    }
    batch.handled = Some(cursor.to_owned());
    HandledCursor::Accepted {
        schema: HANDLED_SCHEMA.to_owned(),
        request_id: request_id.to_owned(),
        arm_id: arm_id.to_owned(),
        generation: *generation,
        signal_id: signal_id.to_owned(),
        cursor: cursor.to_owned(),
        accepted_at: format_time(now),
    }
}

fn format_time(instant: OffsetDateTime) -> String {
    instant
        .format(&Rfc3339)
        .unwrap_or_else(|_| instant.to_string())
}

#[cfg(test)]
mod tests {
    use super::{AckStore, rearm_from_handled, record_handled};
    use crate::admit::KnownArm;
    use gearwit_protocol::{HANDLED_SCHEMA, HandledCursor, parse_handled_cursor};
    use time::format_description::well_known::Rfc3339;
    use time::{Duration, OffsetDateTime};

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-01-15T12:05:20Z", &Rfc3339).expect("now")
    }

    fn arm() -> KnownArm {
        KnownArm {
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: "complete_background_tool".to_owned(),
            coverage_until: now() + Duration::minutes(20),
        }
    }

    fn store_with_batch() -> AckStore {
        let mut store = AckStore::with_arm(arm());
        store.note_delivered(
            "01J00000000000000000000021".to_owned(),
            vec!["post02".to_owned(), "post03".to_owned()],
            vec![
                "post02".to_owned(),
                "post03".to_owned(),
                "post04".to_owned(),
            ],
        );
        store
    }

    fn request(cursor: &str, request_id: &str) -> HandledCursor {
        parse_handled_cursor(&format!(
            r#"{{
                "schema":"{HANDLED_SCHEMA}",
                "type":"handled_cursor_request",
                "request_id":"{request_id}",
                "arm_id":"01J00000000000000000000010",
                "generation":1,
                "seat_id":"example-devrev",
                "signal_id":"01J00000000000000000000021",
                "cursor":"{cursor}",
                "observed_at":"2026-01-15T12:05:20Z"
            }}"#
        ))
        .expect("request")
    }

    #[test]
    fn prefix_and_newest_are_accepted() {
        let mut store = store_with_batch();
        let prefix = record_handled(
            &mut store,
            request("post02", "01J00000000000000000000051"),
            now(),
        )
        .expect("prefix");
        assert!(matches!(
            prefix,
            HandledCursor::Accepted { cursor, .. } if cursor == "post02"
        ));
        let newest = record_handled(
            &mut store,
            request("post03", "01J00000000000000000000050"),
            now(),
        )
        .expect("newest");
        assert!(matches!(
            newest,
            HandledCursor::Accepted { cursor, .. } if cursor == "post03"
        ));
    }

    #[test]
    fn every_reject_code() {
        let mut empty = AckStore::with_arm(arm());
        let reply = record_handled(
            &mut empty,
            request("post03", "01J00000000000000000000052"),
            now(),
        )
        .expect("unknown signal");
        assert!(matches!(
            reply,
            HandledCursor::Rejected { code, .. } if code == "unknown_signal"
        ));

        let mut store = store_with_batch();
        let mut stale_gen = request("post03", "01J00000000000000000000057");
        if let HandledCursor::Request { generation, .. } = &mut stale_gen {
            *generation = 2;
        }
        let reply = record_handled(&mut store, stale_gen, now()).expect("stale gen");
        assert!(matches!(
            reply,
            HandledCursor::Rejected { code, .. } if code == "stale_generation"
        ));

        let mut seat = request("post03", "01J00000000000000000000058");
        if let HandledCursor::Request { seat_id, .. } = &mut seat {
            *seat_id = "other-seat".to_owned();
        }
        let reply = record_handled(&mut store, seat, now()).expect("seat");
        assert!(matches!(
            reply,
            HandledCursor::Rejected { code, .. } if code == "seat_mismatch"
        ));

        let reply = record_handled(
            &mut store,
            request("post99", "01J00000000000000000000054"),
            now(),
        )
        .expect("not member");
        assert!(matches!(
            reply,
            HandledCursor::Rejected { code, .. } if code == "cursor_not_member"
        ));

        let reply = record_handled(
            &mut store,
            request("post04", "01J00000000000000000000055"),
            now(),
        )
        .expect("beyond");
        assert!(matches!(
            reply,
            HandledCursor::Rejected { code, .. } if code == "cursor_beyond_delivered"
        ));

        record_handled(
            &mut store,
            request("post03", "01J00000000000000000000050"),
            now(),
        )
        .expect("newest");
        let reply = record_handled(
            &mut store,
            request("post02", "01J00000000000000000000059"),
            now(),
        )
        .expect("stale cursor");
        assert!(matches!(
            reply,
            HandledCursor::Rejected { code, .. } if code == "stale_cursor"
        ));

        let mut before = AckStore::with_arm(arm());
        before.note_delivered(
            "01J00000000000000000000021".to_owned(),
            Vec::new(),
            Vec::new(),
        );
        let reply = record_handled(
            &mut before,
            request("post03", "01J00000000000000000000053"),
            now(),
        )
        .expect("before");
        assert!(matches!(
            reply,
            HandledCursor::Rejected { code, .. } if code == "ack_before_delivery"
        ));

        let unknown = record_handled(
            &mut AckStore::default(),
            request("post03", "01J00000000000000000000056"),
            now(),
        )
        .expect("no arm");
        assert!(matches!(
            unknown,
            HandledCursor::Rejected { code, .. } if code == "unknown_arm"
        ));
    }

    #[test]
    fn exact_replay_survives_rearm() {
        let mut store = store_with_batch();
        let first = request("post03", "01J00000000000000000000050");
        let accepted = record_handled(&mut store, first.clone(), now()).expect("ack");
        assert!(matches!(accepted, HandledCursor::Accepted { .. }));
        rearm_from_handled(&mut store, "01J00000000000000000000021").expect("rearm");
        assert_eq!(store.arm().expect("arm").generation, 2);
        let replay = record_handled(&mut store, first, now()).expect("replay");
        assert_eq!(replay, accepted);
        let mut fresh = request("post03", "01J00000000000000000000060");
        if let HandledCursor::Request { generation, .. } = &mut fresh {
            *generation = 1;
        }
        let stale = record_handled(&mut store, fresh, now()).expect("unseen old gen");
        assert!(matches!(
            stale,
            HandledCursor::Rejected { code, .. } if code == "stale_generation"
        ));
    }

    #[test]
    fn conflicting_body_is_hard_fail() {
        let mut store = store_with_batch();
        let first = request("post03", "01J00000000000000000000050");
        record_handled(&mut store, first, now()).expect("first");
        let mut conflict = request("post02", "01J00000000000000000000050");
        if let HandledCursor::Request { cursor, .. } = &mut conflict {
            *cursor = "post02".to_owned();
        }
        let error = record_handled(&mut store, conflict, now()).expect_err("conflict");
        assert!(matches!(
            error,
            gearwit_protocol::HandledCursorError::Semantic("request_id conflict")
        ));
    }

    #[test]
    fn rearm_without_record_fails() {
        let mut store = store_with_batch();
        let error =
            rearm_from_handled(&mut store, "01J00000000000000000000021").expect_err("order");
        assert!(matches!(
            error,
            gearwit_protocol::HandledCursorError::Semantic("ack_before_delivery")
        ));
    }
}
