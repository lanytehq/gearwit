//! Private waiter-link admission. No provider I/O in this crate slice.

#![forbid(unsafe_code)]

mod admit;
mod paths;

pub use admit::{AdmittedLink, KnownArm, LinkTable, admit_attach};
pub use paths::{SOCKET_NAME, bind_private_socket, ensure_state_dir};

#[cfg(test)]
mod tests {
    use super::{KnownArm, LinkTable, admit_attach, bind_private_socket, ensure_state_dir};
    use gearwit_protocol::{WaiterLink, parse_waiter_link};
    use std::os::unix::fs::PermissionsExt;
    use time::{Duration, OffsetDateTime};

    fn attach() -> WaiterLink {
        parse_waiter_link(include_str!(
            "../../gearwit-protocol/fixtures/waiter-link/conforming/attach-waiter.json"
        ))
        .expect("fixture")
    }

    fn arm(now: OffsetDateTime) -> KnownArm {
        KnownArm {
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: "complete_background_tool".to_owned(),
            coverage_until: now + Duration::minutes(20),
        }
    }

    #[test]
    fn first_attach_is_accepted_second_is_rejected() {
        let now = OffsetDateTime::parse(
            "2026-01-15T12:05:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("now");
        let mut table = LinkTable::default();
        let first = admit_attach(&mut table, attach(), now, &[arm(now)]).expect("admit");
        assert!(matches!(
            first,
            WaiterLink::AttachAccepted { generation: 1, .. }
        ));
        let second = admit_attach(&mut table, attach(), now, &[arm(now)]).expect("second");
        assert!(matches!(
            second,
            WaiterLink::AttachRejected {
                code,
                ..
            } if code == "already_attached"
        ));
    }

    #[test]
    fn unknown_arm_and_stale_generation_fail_closed() {
        let now = OffsetDateTime::parse(
            "2026-01-15T12:05:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("now");
        let mut table = LinkTable::default();
        let unknown = admit_attach(&mut table, attach(), now, &[]).expect("unknown");
        assert!(matches!(
            unknown,
            WaiterLink::AttachRejected { code, .. } if code == "unknown_arm"
        ));
        let mut stale = arm(now);
        stale.generation = 2;
        let rejected = admit_attach(&mut table, attach(), now, &[stale]).expect("stale");
        assert!(matches!(
            rejected,
            WaiterLink::AttachRejected { code, .. } if code == "stale_generation"
        ));
    }

    #[test]
    fn state_dir_and_socket_are_owner_only() {
        let dir = std::env::temp_dir().join(format!("gearwit-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_state_dir(&dir).expect("dir");
        let mode = std::fs::metadata(&dir).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let listener = bind_private_socket(&dir).expect("bind");
        drop(listener);
        let sock = dir.join(super::SOCKET_NAME);
        let sock_mode = std::fs::metadata(&sock).expect("sock").permissions().mode() & 0o777;
        assert_eq!(sock_mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
