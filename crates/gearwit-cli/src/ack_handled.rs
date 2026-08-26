//! `self ack-handled`: one-shot handled-cursor request over the local socket.
//!
//! Transport only. Completing this process does not claim `turn_started` or
//! coverage rearm.

use std::io::{self, Write};
use std::path::Path;

use gearwit_host::{read_incoming, waiter_frame_config, write_handled};
use gearwit_protocol::{
    HANDLED_SCHEMA, HandledCursor, Incoming, encode_handled_payload, validate_handled,
};
use ipcprims::frame::{FrameReader, FrameWriter};
use ipcprims::transport::UnixDomainSocket;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Process exit when the daemon accepted the ACK.
pub const EXIT_ACCEPTED: u8 = 0;
/// Process exit when the daemon rejected the ACK.
pub const EXIT_REJECTED: u8 = 1;
/// Process exit on transport, validation, or correlation failure.
pub const EXIT_ERROR: u8 = 2;

/// Inputs for one handled-cursor request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckHandledSpec {
    /// Arm id.
    pub arm_id: String,
    /// Arm generation.
    pub generation: u64,
    /// Seat token.
    pub seat_id: String,
    /// Stable signal id.
    pub signal_id: String,
    /// Prefix endpoint `event_ref`.
    pub cursor: String,
    /// Caller-supplied idempotency key. Minted when absent.
    pub request_id: Option<String>,
    /// Caller-supplied observation time. Set before send when absent.
    pub observed_at: Option<String>,
}

/// One request/reply pair. Never claims rearm or a model turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckHandledReport {
    /// Request actually sent.
    pub request: HandledCursor,
    /// Correlated reply.
    pub reply: HandledCursor,
    /// Stable process exit.
    pub exit: u8,
}

/// Connect, send one request, read one reply. Prints the request before send.
///
/// # Errors
///
/// Returns a short message on connect, protocol, or I/O failure.
pub fn run_ack_handled(socket: &Path, spec: &AckHandledSpec) -> Result<AckHandledReport, String> {
    run_ack_handled_to(socket, spec, io::stdout())
}

/// Same as [`run_ack_handled`] with an injected sink.
///
/// # Errors
///
/// Returns a short message on connect, protocol, or I/O failure.
pub fn run_ack_handled_to(
    socket: &Path,
    spec: &AckHandledSpec,
    mut out: impl Write,
) -> Result<AckHandledReport, String> {
    let request = build_request(spec)?;
    write_phase(&mut out, "request", &request)?;
    let stream = UnixDomainSocket::connect(socket).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let writer_stream = stream.try_clone().map_err(|error| error.to_string())?;
    let mut reader = FrameReader::with_config(stream, waiter_frame_config());
    let mut writer = FrameWriter::with_config(writer_stream, waiter_frame_config());
    write_handled(&mut writer, &request).map_err(|error| error.to_string())?;
    let incoming = read_incoming(&mut reader).map_err(|error| error.to_string())?;
    let Incoming::Handled(reply) = incoming else {
        return Err("expected handled-cursor reply".to_owned());
    };
    let exit = correlate(&request, &reply)?;
    write_phase(&mut out, "reply", &reply)?;
    Ok(AckHandledReport {
        request,
        reply,
        exit,
    })
}

fn build_request(spec: &AckHandledSpec) -> Result<HandledCursor, String> {
    let request = HandledCursor::Request {
        schema: HANDLED_SCHEMA.to_owned(),
        request_id: spec
            .request_id
            .clone()
            .unwrap_or_else(|| ulid::Ulid::new().to_string()),
        arm_id: spec.arm_id.clone(),
        generation: spec.generation,
        seat_id: spec.seat_id.clone(),
        signal_id: spec.signal_id.clone(),
        cursor: spec.cursor.clone(),
        observed_at: spec.observed_at.clone().unwrap_or_else(|| {
            OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
        }),
    };
    validate_handled(&request).map_err(|error| error.to_string())?;
    let _ = encode_handled_payload(&request).map_err(|error| error.to_string())?;
    Ok(request)
}

fn write_phase(out: &mut impl Write, phase: &str, message: &HandledCursor) -> Result<(), String> {
    let mut value = serde_json::to_value(message).map_err(|error| error.to_string())?;
    if let Value::Object(map) = &mut value {
        map.insert("phase".to_owned(), json!(phase));
        map.insert("turn_started".to_owned(), json!("unknown"));
        map.insert("rearm_claimed".to_owned(), json!(false));
    }
    writeln!(
        out,
        "{}",
        serde_json::to_string(&value).map_err(|error| error.to_string())?
    )
    .and_then(|()| out.flush())
    .map_err(|error| error.to_string())
}

fn correlate(request: &HandledCursor, reply: &HandledCursor) -> Result<u8, String> {
    let HandledCursor::Request {
        request_id,
        arm_id,
        generation,
        signal_id,
        cursor,
        ..
    } = request
    else {
        return Err("expected request".to_owned());
    };
    match reply {
        HandledCursor::Accepted {
            request_id: reply_id,
            arm_id: reply_arm,
            generation: reply_gen,
            signal_id: reply_signal,
            cursor: reply_cursor,
            ..
        } => {
            if reply_id != request_id
                || reply_arm != arm_id
                || reply_gen != generation
                || reply_signal != signal_id
                || reply_cursor != cursor
            {
                return Err("accepted reply did not echo the request".to_owned());
            }
            Ok(EXIT_ACCEPTED)
        }
        HandledCursor::Rejected {
            request_id: reply_id,
            ..
        } => {
            if reply_id != request_id {
                return Err("rejected reply request_id mismatch".to_owned());
            }
            Ok(EXIT_REJECTED)
        }
        HandledCursor::Request { .. } => Err("expected reply".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{AckHandledSpec, EXIT_ACCEPTED, EXIT_REJECTED, run_ack_handled_to};
    use gearwit_host::{AckStore, GearwitPaths, KnownArm, LinkTable, serve_connection};
    use gearwit_protocol::HandledCursor;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-01-15T12:05:20Z", &Rfc3339).expect("now")
    }

    fn arm() -> KnownArm {
        KnownArm {
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: "complete_background_tool".to_owned(),
            coverage_until: now() + time::Duration::minutes(20),
        }
    }

    fn spec() -> AckHandledSpec {
        AckHandledSpec {
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            signal_id: "01J00000000000000000000021".to_owned(),
            cursor: "post02".to_owned(),
            request_id: Some("01J00000000000000000000051".to_owned()),
            observed_at: Some("2026-01-15T12:05:20Z".to_owned()),
        }
    }

    fn ack_store() -> AckStore {
        let mut store = AckStore::with_arm(arm());
        store
            .note_claimed("01J00000000000000000000021".to_owned())
            .expect("claim");
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
            .expect("delivered");
        store
    }

    fn temp_root() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gearwit-cli-ack-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn prefix_ack_suffix_claim_and_exact_replay() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut table = LinkTable::default();
            let mut acks = ack_store();
            let stream = listener.accept().expect("prefix");
            serve_connection(stream, &mut table, &mut acks, now()).expect("prefix serve");
            acks.note_claimed("01J00000000000000000000022".to_owned())
                .expect("suffix claim");
            acks.note_delivered(
                "01J00000000000000000000022".to_owned(),
                vec!["post03".to_owned()],
                &["post03".to_owned()],
            )
            .expect("suffix delivered");
            let stream = listener.accept().expect("replay");
            serve_connection(stream, &mut table, &mut acks, now()).expect("replay serve");
            let stream = listener.accept().expect("suffix");
            serve_connection(stream, &mut table, &mut acks, now()).expect("suffix serve");
            tx.send(acks.arm().map(|arm| arm.generation)).expect("gen");
        });
        thread::sleep(Duration::from_millis(20));
        let mut first_out = Cursor::new(Vec::new());
        let first = run_ack_handled_to(&socket, &spec(), &mut first_out).expect("first");
        assert_eq!(first.exit, EXIT_ACCEPTED);
        assert!(matches!(first.reply, HandledCursor::Accepted { .. }));
        let printed = String::from_utf8(first_out.into_inner()).expect("utf8");
        assert!(printed.contains("\"phase\":\"request\""));
        assert!(printed.contains("\"phase\":\"reply\""));
        assert!(printed.contains("\"rearm_claimed\":false"));
        assert!(printed.contains("\"turn_started\":\"unknown\""));
        let mut second_out = Cursor::new(Vec::new());
        let second = run_ack_handled_to(&socket, &spec(), &mut second_out).expect("replay");
        assert_eq!(second.exit, EXIT_ACCEPTED);
        assert_eq!(second.request, first.request);
        assert_eq!(second.reply, first.reply);
        let suffix = AckHandledSpec {
            generation: 2,
            signal_id: "01J00000000000000000000022".to_owned(),
            cursor: "post03".to_owned(),
            request_id: Some("01J00000000000000000000052".to_owned()),
            ..spec()
        };
        let third = run_ack_handled_to(&socket, &suffix, Cursor::new(Vec::new())).expect("suffix");
        assert_eq!(third.exit, EXIT_ACCEPTED);
        let generation = rx.recv_timeout(Duration::from_secs(2)).expect("gen");
        assert_eq!(generation, Some(3));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejected_is_exit_one_without_rearm_claim() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        thread::spawn(move || {
            let mut table = LinkTable::default();
            let mut acks = AckStore::with_arm(arm());
            let stream = listener.accept().expect("accept");
            let _ = serve_connection(stream, &mut table, &mut acks, now());
        });
        thread::sleep(Duration::from_millis(20));
        let mut out = Cursor::new(Vec::new());
        let report = run_ack_handled_to(&socket, &spec(), &mut out).expect("rejected");
        assert_eq!(report.exit, EXIT_REJECTED);
        assert!(matches!(
            report.reply,
            HandledCursor::Rejected { ref code, .. } if code == "unknown_signal"
        ));
        let printed = String::from_utf8(out.into_inner()).expect("utf8");
        assert!(printed.contains("\"rearm_claimed\":false"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn different_body_same_request_id_fails() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        thread::spawn(move || {
            let mut table = LinkTable::default();
            let mut acks = ack_store();
            for _ in 0..2 {
                let stream = listener.accept().expect("accept");
                let _ = serve_connection(stream, &mut table, &mut acks, now());
            }
        });
        thread::sleep(Duration::from_millis(20));
        let _ = run_ack_handled_to(&socket, &spec(), Cursor::new(Vec::new())).expect("first");
        let mut conflict = spec();
        conflict.cursor = "post03".to_owned();
        let error =
            run_ack_handled_to(&socket, &conflict, Cursor::new(Vec::new())).expect_err("conflict");
        assert!(!error.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
