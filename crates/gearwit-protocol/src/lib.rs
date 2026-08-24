//! Pinned waiter-link contract: typed frames, no runtime JSON Schema crate.

#![forbid(unsafe_code)]

mod codec;
mod messages;

pub use codec::{FrameError, MAX_FRAME, decode_frame, encode_frame};
pub use messages::{PIN_COMMIT, SCHEMA, WaiterLink, WaiterLinkError, parse_waiter_link};

#[cfg(test)]
mod tests {
    use super::{PIN_COMMIT, WaiterLink, decode_frame, encode_frame, parse_waiter_link};
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
    fn length_prefix_round_trip_and_max() {
        let text = fs::read_to_string(fixture_root().join("conforming/attach-waiter.json"))
            .expect("fixture");
        let message = parse_waiter_link(&text).expect("parse");
        let framed = encode_frame(&message).expect("encode");
        let decoded = decode_frame(&framed).expect("decode");
        assert_eq!(decoded, message);
        assert!(matches!(
            message,
            WaiterLink::AttachWaiter { generation: 1, .. }
        ));
        assert!(encode_frame_oversize_rejected());
    }

    fn encode_frame_oversize_rejected() -> bool {
        matches!(
            super::decode_frame(&[0xff, 0xff, 0xff, 0xff]),
            Err(super::FrameError::TooLarge { .. })
        )
    }
}
