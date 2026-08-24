//! Private waiter-link admission over ipcprims. No provider I/O in this crate.

#![forbid(unsafe_code)]

mod admit;
mod link;
mod paths;

pub use admit::{AdmittedLink, KnownArm, LinkTable, admit_attach};
pub use link::{LinkError, read_waiter_link, serve_attach, waiter_frame_config, write_waiter_link};
pub use paths::{BindError, GearwitPaths, SOCKET_FILE, bind_private_socket, canonical_root};

#[cfg(test)]
mod tests {
    use super::{
        BindError, GearwitPaths, KnownArm, LinkError, LinkTable, SOCKET_FILE, admit_attach,
        bind_private_socket, serve_attach,
    };
    use gearwit_protocol::{
        MAX_PAYLOAD, WaiterLink, decode_payload, encode_payload, parse_waiter_link,
    };
    use ipcprims::frame::{COMMAND, DATA, FrameReader};
    use ipcprims::transport::UnixDomainSocket;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use time::{Duration as TimeDuration, OffsetDateTime};

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn fixture_attach() -> WaiterLink {
        parse_waiter_link(include_str!(
            "../../gearwit-protocol/fixtures/waiter-link/conforming/attach-waiter.json"
        ))
        .expect("fixture")
    }

    fn attach_with(request_id: &str) -> WaiterLink {
        let mut message = fixture_attach();
        if let WaiterLink::AttachWaiter { request_id: id, .. } = &mut message {
            *id = request_id.to_owned();
        }
        message
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-01-15T12:05:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("now")
    }

    fn arm(instant: OffsetDateTime) -> KnownArm {
        KnownArm {
            arm_id: "01J00000000000000000000010".to_owned(),
            generation: 1,
            seat_id: "example-devrev".to_owned(),
            route: "complete_background_tool".to_owned(),
            coverage_until: instant + TimeDuration::minutes(20),
        }
    }

    fn temp_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gearwit-host-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).expect("meta").permissions().mode() & 0o777
    }

    fn ipc_frame(channel: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.extend_from_slice(&[0x49, 0x50]);
        let len = u32::try_from(payload.len()).expect("payload fits u32");
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&channel.to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn duplicate_request_id_is_idempotent() {
        let instant = now();
        let mut table = LinkTable::default();
        let first =
            admit_attach(&mut table, fixture_attach(), instant, &[arm(instant)]).expect("admit");
        let second =
            admit_attach(&mut table, fixture_attach(), instant, &[arm(instant)]).expect("replay");
        assert_eq!(first, second);
        assert!(matches!(
            first,
            WaiterLink::AttachAccepted { generation: 1, .. }
        ));
    }

    #[test]
    fn different_request_while_attached_is_rejected() {
        let instant = now();
        let mut table = LinkTable::default();
        admit_attach(&mut table, fixture_attach(), instant, &[arm(instant)]).expect("admit");
        let second = admit_attach(
            &mut table,
            attach_with("01J00000000000000000000099"),
            instant,
            &[arm(instant)],
        )
        .expect("second");
        assert!(matches!(
            second,
            WaiterLink::AttachRejected { code, .. } if code == "already_attached"
        ));
    }

    #[test]
    fn unknown_arm_and_stale_generation_fail_closed() {
        let instant = now();
        let mut table = LinkTable::default();
        let unknown = admit_attach(&mut table, fixture_attach(), instant, &[]).expect("unknown");
        assert!(matches!(
            unknown,
            WaiterLink::AttachRejected { code, .. } if code == "unknown_arm"
        ));
        let mut stale = arm(instant);
        stale.generation = 2;
        let rejected =
            admit_attach(&mut table, fixture_attach(), instant, &[stale]).expect("stale");
        assert!(matches!(
            rejected,
            WaiterLink::AttachRejected { code, .. } if code == "stale_generation"
        ));
    }

    #[test]
    fn disconnect_allows_reconnect() {
        let instant = now();
        let mut table = LinkTable::default();
        let first =
            admit_attach(&mut table, fixture_attach(), instant, &[arm(instant)]).expect("first");
        table.drop_current();
        let second = admit_attach(
            &mut table,
            attach_with("01J00000000000000000000098"),
            instant,
            &[arm(instant)],
        )
        .expect("reconnect");
        match (first, second) {
            (
                WaiterLink::AttachAccepted { link_id: a, .. },
                WaiterLink::AttachAccepted { link_id: b, .. },
            ) => assert_ne!(a, b),
            other => panic!("expected two accepts, got {other:?}"),
        }
    }

    #[test]
    fn canonical_root_is_under_lanyte_gearwit() {
        let root = super::canonical_root().expect("HOME");
        assert!(root.ends_with(std::path::Path::new(".lanyte").join("gearwit")));
    }

    #[test]
    fn canonical_layout_is_owner_only() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        assert_eq!(paths.socket_path(), root.join("run").join(SOCKET_FILE));
        assert_eq!(paths.state_dir(), root.join("state"));
        assert_eq!(mode(paths.root()), 0o700);
        assert_eq!(mode(&root.join("run")), 0o700);
        assert_eq!(mode(&paths.state_dir()), 0o700);
        let listener = paths.bind().expect("bind");
        assert_eq!(mode(&paths.socket_path()), 0o600);
        drop(listener);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn live_socket_collision_is_refused() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let first = paths.bind().expect("first");
        assert!(matches!(paths.bind(), Err(BindError::LiveListener(_))));
        drop(first);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stale_socket_is_replaced() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let leftover = UnixListener::bind(paths.socket_path()).expect("leftover");
        drop(leftover);
        let listener = paths.bind().expect("stale");
        drop(listener);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_socket_collision_is_refused() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        std::fs::write(paths.socket_path(), b"not-a-socket").expect("file");
        assert!(matches!(paths.bind(), Err(BindError::NotASocket(_))));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn symlink_root_is_refused() {
        let root = temp_root();
        let real = root.join("real");
        std::fs::create_dir_all(&real).expect("real");
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(matches!(
            GearwitPaths::from_root(link),
            Err(BindError::Symlink(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn attach_over_socket_and_partial_io() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let instant = now();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let stream = listener.accept().expect("accept");
            let mut table = LinkTable::default();
            let reply = serve_attach(stream, &mut table, instant, &[arm(instant)]);
            tx.send(reply).expect("send");
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = UnixDomainSocket::connect(&socket).expect("connect");
        let payload = encode_payload(&fixture_attach()).expect("payload");
        let framed = ipc_frame(COMMAND, &payload);
        client.write_all(&framed[..10]).expect("partial");
        thread::sleep(Duration::from_millis(30));
        client.write_all(&framed[10..]).expect("rest");
        let mut reader = FrameReader::with_config(client, super::waiter_frame_config());
        let frame = reader.read_frame().expect("reply frame");
        assert_eq!(frame.channel, COMMAND);
        let reply = decode_payload(&frame.payload).expect("reply");
        assert!(matches!(reply, WaiterLink::AttachAccepted { .. }));
        let served = rx.recv_timeout(Duration::from_secs(2)).expect("served");
        assert!(served.is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn oversize_frame_rejected_before_payload_alloc() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let instant = now();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let stream = listener.accept().expect("accept");
            let mut table = LinkTable::default();
            let reply = serve_attach(stream, &mut table, instant, &[arm(instant)]);
            tx.send(reply).expect("send");
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = UnixDomainSocket::connect(&socket).expect("connect");
        let too_big = u32::try_from(MAX_PAYLOAD + 1).expect("fits");
        let mut header = Vec::from([0x49, 0x50]);
        header.extend_from_slice(&too_big.to_le_bytes());
        header.extend_from_slice(&COMMAND.to_le_bytes());
        client.write_all(&header).expect("header");
        let served = rx.recv_timeout(Duration::from_secs(2)).expect("served");
        assert!(matches!(served, Err(LinkError::Frame(_))));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_channel_is_rejected() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let instant = now();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let stream = listener.accept().expect("accept");
            let mut table = LinkTable::default();
            let reply = serve_attach(stream, &mut table, instant, &[arm(instant)]);
            tx.send(reply).expect("send");
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = UnixDomainSocket::connect(&socket).expect("connect");
        let payload = encode_payload(&fixture_attach()).expect("payload");
        client.write_all(&ipc_frame(DATA, &payload)).expect("write");
        let served = rx.recv_timeout(Duration::from_secs(2)).expect("served");
        assert!(matches!(served, Err(LinkError::WrongChannel(DATA))));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bind_private_socket_uses_injected_path() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = bind_private_socket(&paths.socket_path()).expect("bind");
        drop(listener);
        let _ = std::fs::remove_dir_all(&root);
    }
}
