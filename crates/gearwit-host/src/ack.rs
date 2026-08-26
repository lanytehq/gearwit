//! Handled-cursor acknowledgement. Separate from waiter-link attach.

use std::collections::BTreeMap;

use crate::admit::{HISTORY_CAP, KnownArm};
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
    arm_id: String,
    generation: u64,
    delivered: Vec<String>,
    drain_snapshot: Vec<String>,
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
    ///
    /// Exact replay of the same snapshots is idempotent. A different body for
    /// the same signal is a hard conflict. Never resets handled/closed state.
    ///
    /// # Errors
    ///
    /// Returns [`HandledCursorError`] when the snapshots are malformed or
    /// conflict with an existing claim.
    pub fn note_delivered(
        &mut self,
        signal_id: String,
        delivered: Vec<String>,
        drain_snapshot: &[String],
    ) -> Result<(), HandledCursorError> {
        let arm = self
            .arm
            .as_ref()
            .ok_or(HandledCursorError::Semantic("unknown_arm"))?;
        if delivered.is_empty() {
            return Err(HandledCursorError::Semantic("empty delivery"));
        }
        validate_leading_prefix(&delivered, drain_snapshot)?;
        let after_bound = drain_snapshot
            .get(delivered.len()..)
            .unwrap_or(&[])
            .to_vec();
        if let Some((open_id, _)) = self
            .signals
            .iter()
            .find(|(_, batch)| batch.generation == arm.generation && !batch.closed)
            && open_id != &signal_id
        {
            return Err(HandledCursorError::Semantic("signal conflict"));
        }
        if let Some(existing) = self.signals.get_mut(&signal_id) {
            let same_authority =
                existing.arm_id == arm.arm_id && existing.generation == arm.generation;
            if same_authority
                && existing.delivered.is_empty()
                && !existing.closed
                && existing.handled.is_none()
            {
                existing.delivered = delivered;
                existing.drain_snapshot = drain_snapshot.to_vec();
                existing.after_bound = after_bound;
                return Ok(());
            }
            if same_authority
                && existing.delivered == delivered
                && existing.drain_snapshot == drain_snapshot
            {
                return Ok(());
            }
            return Err(HandledCursorError::Semantic("signal conflict"));
        }
        self.signals.insert(
            signal_id,
            SignalBatch {
                arm_id: arm.arm_id.clone(),
                generation: arm.generation,
                delivered,
                drain_snapshot: drain_snapshot.to_vec(),
                after_bound,
                handled: None,
                closed: false,
            },
        );
        Ok(())
    }

    /// Register a claimed signal before any events are delivered.
    ///
    /// # Errors
    ///
    /// Returns [`HandledCursorError`] when another current-generation signal
    /// is already open.
    pub fn note_claimed(&mut self, signal_id: String) -> Result<(), HandledCursorError> {
        let arm = self
            .arm
            .as_ref()
            .ok_or(HandledCursorError::Semantic("unknown_arm"))?;
        if let Some((open_id, _)) = self
            .signals
            .iter()
            .find(|(_, batch)| batch.generation == arm.generation && !batch.closed)
            && open_id != &signal_id
        {
            return Err(HandledCursorError::Semantic("signal conflict"));
        }
        if let Some(existing) = self.signals.get(&signal_id) {
            if existing.arm_id == arm.arm_id
                && existing.generation == arm.generation
                && existing.delivered.is_empty()
                && !existing.closed
            {
                return Ok(());
            }
            return Err(HandledCursorError::Semantic("signal conflict"));
        }
        self.signals.insert(
            signal_id,
            SignalBatch {
                arm_id: arm.arm_id.clone(),
                generation: arm.generation,
                delivered: Vec::new(),
                drain_snapshot: Vec::new(),
                after_bound: Vec::new(),
                handled: None,
                closed: false,
            },
        );
        Ok(())
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
    if store.history.len() >= HISTORY_CAP {
        return Err(HandledCursorError::Semantic("request history full"));
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
    if batch.generation != arm.generation {
        return Err(HandledCursorError::Semantic("stale_generation"));
    }
    let Some(cursor) = batch.handled.clone() else {
        return Err(HandledCursorError::Semantic("ack_before_delivery"));
    };
    if batch.closed {
        return Err(HandledCursorError::Semantic("stale_generation"));
    }
    let next = arm
        .generation
        .checked_add(1)
        .ok_or(HandledCursorError::Semantic("generation overflow"))?;
    batch.closed = true;
    arm.generation = next;
    Ok(cursor)
}

/// Coverage successor after the first accepted ACK for an open signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckRearm {
    /// Exclusive `--after` cursor for the successor drain.
    pub after: String,
    /// Live generation after the bump.
    pub generation: u64,
    /// Closed signal.
    pub signal_id: String,
}

/// Record an ACK; rearm only on the first accepted reply for an open signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandledServe {
    /// Reply to write on the ACK connection.
    pub reply: HandledCursor,
    /// Present only when this request closed the signal and bumped generation.
    pub rearm: Option<AckRearm>,
}

/// Record `request`, then rearm exactly once if it was newly accepted.
///
/// Exact history replay returns the same reply and does not bump generation
/// again. A failed reply write does not undo the record.
///
/// # Errors
///
/// Returns [`HandledCursorError`] when the request is not a valid ACK request
/// or rearm fails for a reason other than an already-closed signal.
pub fn apply_handled_request(
    store: &mut AckStore,
    request: HandledCursor,
    now: OffsetDateTime,
) -> Result<HandledServe, HandledCursorError> {
    let reply = record_handled(store, request, now)?;
    let rearm = match &reply {
        HandledCursor::Accepted {
            signal_id, cursor, ..
        } => match rearm_from_handled(store, signal_id) {
            Ok(_) => {
                let generation = store
                    .arm()
                    .map(|arm| arm.generation)
                    .ok_or(HandledCursorError::Semantic("unknown_arm"))?;
                Some(AckRearm {
                    after: cursor.clone(),
                    generation,
                    signal_id: signal_id.clone(),
                })
            }
            Err(HandledCursorError::Semantic("stale_generation")) => None,
            Err(error) => return Err(error),
        },
        _ => None,
    };
    Ok(HandledServe { reply, rearm })
}

fn validate_leading_prefix(
    delivered: &[String],
    drain_snapshot: &[String],
) -> Result<(), HandledCursorError> {
    let mut seen = std::collections::BTreeSet::new();
    for event_ref in drain_snapshot {
        if !seen.insert(event_ref.as_str()) {
            return Err(HandledCursorError::Semantic("duplicate drain ref"));
        }
    }
    seen.clear();
    for event_ref in delivered {
        if !seen.insert(event_ref.as_str()) {
            return Err(HandledCursorError::Semantic("duplicate event_ref"));
        }
    }
    if drain_snapshot.len() < delivered.len() || drain_snapshot[..delivered.len()] != *delivered {
        return Err(HandledCursorError::Semantic("delivered not leading prefix"));
    }
    Ok(())
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
    if batch.closed || batch.generation != arm.generation {
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
    use super::{AckStore, apply_handled_request, rearm_from_handled, record_handled};
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
        store
            .note_delivered(
                "01J00000000000000000000021".to_owned(),
                vec!["post02".to_owned(), "post03".to_owned()],
                &[
                    "post02".to_owned(),
                    "post03".to_owned(),
                    "post04".to_owned(),
                ],
            )
            .expect("note");
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
        before
            .note_claimed("01J00000000000000000000021".to_owned())
            .expect("claimed");
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

    #[test]
    fn space_cursor_is_rejected_by_the_pin() {
        let text = include_str!(
            "../../gearwit-protocol/fixtures/handled-cursor/negative/space-cursor.json"
        );
        assert!(parse_handled_cursor(text).is_err());
    }

    #[test]
    fn note_delivered_is_idempotent_and_does_not_reset() {
        let mut store = store_with_batch();
        record_handled(
            &mut store,
            request("post03", "01J00000000000000000000050"),
            now(),
        )
        .expect("ack");
        store
            .note_delivered(
                "01J00000000000000000000021".to_owned(),
                vec!["post02".to_owned(), "post03".to_owned()],
                &[
                    "post02".to_owned(),
                    "post03".to_owned(),
                    "post04".to_owned(),
                ],
            )
            .expect("replay");
        let error = store
            .note_delivered(
                "01J00000000000000000000021".to_owned(),
                vec!["post02".to_owned()],
                &["post02".to_owned()],
            )
            .expect_err("conflict");
        assert!(matches!(
            error,
            gearwit_protocol::HandledCursorError::Semantic("signal conflict")
        ));
        let stale = record_handled(
            &mut store,
            request("post02", "01J00000000000000000000061"),
            now(),
        )
        .expect("still newest");
        assert!(matches!(
            stale,
            HandledCursor::Rejected { code, .. } if code == "stale_cursor"
        ));
    }

    #[test]
    fn rearm_does_not_advance_a_replaced_generation() {
        let mut store = store_with_batch();
        record_handled(
            &mut store,
            request("post03", "01J00000000000000000000050"),
            now(),
        )
        .expect("ack a");
        let conflict = store.note_delivered(
            "01J00000000000000000000022".to_owned(),
            vec!["post02".to_owned(), "post03".to_owned()],
            &["post02".to_owned(), "post03".to_owned()],
        );
        assert!(matches!(
            conflict,
            Err(gearwit_protocol::HandledCursorError::Semantic(
                "signal conflict"
            ))
        ));
        rearm_from_handled(&mut store, "01J00000000000000000000021").expect("rearm a");
        store
            .note_delivered(
                "01J00000000000000000000022".to_owned(),
                vec!["post02".to_owned(), "post03".to_owned()],
                &["post02".to_owned(), "post03".to_owned()],
            )
            .expect("next gen");
        let mut other = request("post03", "01J00000000000000000000062");
        if let HandledCursor::Request {
            signal_id,
            generation,
            ..
        } = &mut other
        {
            *signal_id = "01J00000000000000000000022".to_owned();
            *generation = 2;
        }
        record_handled(&mut store, other, now()).expect("ack b");
        let error =
            rearm_from_handled(&mut store, "01J00000000000000000000021").expect_err("stale a");
        assert!(matches!(
            error,
            gearwit_protocol::HandledCursorError::Semantic("stale_generation")
        ));
        assert_eq!(store.arm().expect("arm").generation, 2);
    }

    #[test]
    fn generation_overflow_does_not_close() {
        let mut max = arm();
        max.generation = u64::MAX;
        let mut store = AckStore::with_arm(max);
        store
            .note_delivered(
                "01J00000000000000000000021".to_owned(),
                vec!["post02".to_owned(), "post03".to_owned()],
                &["post02".to_owned(), "post03".to_owned()],
            )
            .expect("note");
        let mut req = request("post03", "01J00000000000000000000050");
        if let HandledCursor::Request { generation, .. } = &mut req {
            *generation = u64::MAX;
        }
        record_handled(&mut store, req, now()).expect("ack");
        let error =
            rearm_from_handled(&mut store, "01J00000000000000000000021").expect_err("overflow");
        assert!(matches!(
            error,
            gearwit_protocol::HandledCursorError::Semantic("generation overflow")
        ));
        assert_eq!(store.arm().expect("arm").generation, u64::MAX);
    }

    #[test]
    fn sparse_delivered_slice_is_rejected() {
        let mut store = AckStore::with_arm(arm());
        let error = store
            .note_delivered(
                "01J00000000000000000000021".to_owned(),
                vec!["post02".to_owned(), "post04".to_owned()],
                &[
                    "post02".to_owned(),
                    "post03".to_owned(),
                    "post04".to_owned(),
                ],
            )
            .expect_err("sparse");
        assert!(matches!(
            error,
            gearwit_protocol::HandledCursorError::Semantic("delivered not leading prefix")
        ));
    }

    #[test]
    fn leading_skip_is_rejected() {
        let mut store = AckStore::with_arm(arm());
        let error = store
            .note_delivered(
                "01J00000000000000000000021".to_owned(),
                vec!["post03".to_owned(), "post04".to_owned()],
                &[
                    "post02".to_owned(),
                    "post03".to_owned(),
                    "post04".to_owned(),
                ],
            )
            .expect_err("skip");
        assert!(matches!(
            error,
            gearwit_protocol::HandledCursorError::Semantic("delivered not leading prefix")
        ));
    }

    #[test]
    fn claimed_then_delivered_then_ack() {
        let mut store = AckStore::with_arm(arm());
        store
            .note_claimed("01J00000000000000000000021".to_owned())
            .expect("claimed");
        let before = record_handled(
            &mut store,
            request("post03", "01J00000000000000000000053"),
            now(),
        )
        .expect("before");
        assert!(matches!(
            before,
            HandledCursor::Rejected { code, .. } if code == "ack_before_delivery"
        ));
        store
            .note_delivered(
                "01J00000000000000000000021".to_owned(),
                vec!["post02".to_owned(), "post03".to_owned()],
                &[
                    "post02".to_owned(),
                    "post03".to_owned(),
                    "post04".to_owned(),
                ],
            )
            .expect("deliver");
        let accepted = record_handled(
            &mut store,
            request("post03", "01J00000000000000000000050"),
            now(),
        )
        .expect("ack");
        assert!(matches!(accepted, HandledCursor::Accepted { .. }));
    }

    #[test]
    fn history_cap_preserves_accepted_replay() {
        let mut store = store_with_batch();
        let first = request("post03", "01J00000000000000000000050");
        let accepted = record_handled(&mut store, first.clone(), now()).expect("first");
        for index in 1..crate::admit::HISTORY_CAP {
            let request_id = format!("01K{index:023}");
            let reply =
                record_handled(&mut store, request("post03", &request_id), now()).expect("fill");
            assert!(matches!(reply, HandledCursor::Accepted { .. }));
        }
        let error = record_handled(
            &mut store,
            request("post03", "01K99999999999999999999999"),
            now(),
        )
        .expect_err("full");
        assert!(matches!(
            error,
            gearwit_protocol::HandledCursorError::Semantic("request history full")
        ));
        let replay = record_handled(&mut store, first, now()).expect("replay");
        assert_eq!(replay, accepted);
        assert_eq!(store.arm().expect("arm").generation, 1);
    }

    #[test]
    fn apply_records_before_rearm_and_replay_does_not_bump() {
        let mut store = store_with_batch();
        let first = apply_handled_request(
            &mut store,
            request("post02", "01J00000000000000000000051"),
            now(),
        )
        .expect("first");
        assert!(matches!(first.reply, HandledCursor::Accepted { .. }));
        let rearm = first.rearm.expect("rearm");
        assert_eq!(rearm.after, "post02");
        assert_eq!(rearm.generation, 2);
        assert_eq!(store.arm().expect("arm").generation, 2);
        let replay = apply_handled_request(
            &mut store,
            request("post02", "01J00000000000000000000051"),
            now(),
        )
        .expect("replay");
        assert_eq!(replay.reply, first.reply);
        assert!(replay.rearm.is_none());
        assert_eq!(store.arm().expect("arm").generation, 2);
    }
}
