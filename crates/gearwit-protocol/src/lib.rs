//! Pinned waiter-link contract: typed JSON payloads, no runtime JSON Schema crate.

#![forbid(unsafe_code)]

mod codec;
mod messages;

pub use codec::{MAX_PAYLOAD, PayloadError, decode_payload, encode_payload};
pub use messages::{PIN_COMMIT, SCHEMA, WaiterLink, WaiterLinkError, parse_waiter_link, validate};

#[cfg(test)]
mod tests {
    use super::{
        MAX_PAYLOAD, PIN_COMMIT, PayloadError, WaiterLink, decode_payload, encode_payload,
        parse_waiter_link,
    };
    use std::fs;
    use std::path::PathBuf;

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/waiter-link")
    }

    #[test]
    fn pin_commit_matches_schema_pins_toml() {
        let pins = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema-pins.toml"),
        )
        .expect("schema-pins.toml");
        assert!(
            pins.contains(PIN_COMMIT),
            "protocol PIN_COMMIT must match schema-pins.toml"
        );
    }

    #[test]
    fn conforming_fixtures_parse() {
        let dir = fixture_root().join("conforming");
        for entry in fs::read_dir(dir).expect("conforming") {
            let path = entry.expect("entry").path();
            let text = fs::read_to_string(&path).expect("read");
            parse_waiter_link(&text).unwrap_or_else(|error| {
                panic!("{} should parse: {error}", path.display());
            });
        }
    }

    #[test]
    fn negative_fixtures_are_rejected() {
        let dir = fixture_root().join("negative");
        for entry in fs::read_dir(dir).expect("negative") {
            let path = entry.expect("entry").path();
            let text = fs::read_to_string(&path).expect("read");
            assert!(
                parse_waiter_link(&text).is_err(),
                "{} must fail validation",
                path.display()
            );
        }
    }

    #[test]
    fn payload_round_trip_and_max() {
        let text = fs::read_to_string(fixture_root().join("conforming/attach-waiter.json"))
            .expect("fixture");
        let message = parse_waiter_link(&text).expect("parse");
        let payload = encode_payload(&message).expect("encode");
        let decoded = decode_payload(&payload).expect("decode");
        assert_eq!(decoded, message);
        assert!(matches!(
            message,
            WaiterLink::AttachWaiter { generation: 1, .. }
        ));
        let oversized = vec![b'x'; MAX_PAYLOAD + 1];
        assert!(matches!(
            decode_payload(&oversized),
            Err(PayloadError::TooLarge { size }) if size == MAX_PAYLOAD + 1
        ));
    }

    #[test]
    fn encode_rejects_invalid_constructed_messages() {
        let text = fs::read_to_string(fixture_root().join("conforming/attach-waiter.json"))
            .expect("fixture");
        let mut message = parse_waiter_link(&text).expect("parse");
        if let WaiterLink::AttachWaiter { generation, .. } = &mut message {
            *generation = 0;
        }
        assert!(encode_payload(&message).is_err());
    }

    #[test]
    fn decode_rejects_empty_and_invalid_utf8() {
        assert!(matches!(decode_payload(&[]), Err(PayloadError::Empty)));
        assert!(matches!(
            decode_payload(&[0xff]),
            Err(PayloadError::InvalidUtf8)
        ));
    }

    #[test]
    fn body_max_length_is_unicode_characters() {
        let snowman = "☃".repeat(4096);
        let json = format!(
            r#"{{
  "schema": "gearwit.interrupt.waiter-link.v0",
  "type": "deliver_events",
  "delivery_id": "01J00000000000000000000043",
  "link_id": "01J00000000000000000000042",
  "arm_id": "01J00000000000000000000010",
  "generation": 1,
  "signal_id": "01J00000000000000000000021",
  "route": "complete_background_tool",
  "events": [{{
    "provider": "mattermost",
    "event_ref": "post02",
    "observed_at": "2026-01-15T12:05:00Z",
    "body": "{snowman}"
  }}],
  "newest_event_ref": "post02",
  "attempted_at": "2026-01-15T12:05:02Z"
}}"#
        );
        parse_waiter_link(&json).expect("4096-char body must pass pin maxLength");
    }
}
