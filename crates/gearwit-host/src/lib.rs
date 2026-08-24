//! Private waiter-link admission over ipcprims. No provider I/O in this crate.

#![forbid(unsafe_code)]

mod admit;
mod link;
mod paths;

pub use admit::{AdmittedLink, KnownArm, LinkSession, LinkTable, admit_attach, drop_session};
pub use link::{
    LinkError, ServeAttach, read_waiter_link, serve_attach, wait_disconnect, waiter_frame_config,
    write_waiter_link,
};
pub use paths::{BindError, BoundListener, GearwitPaths, SOCKET_FILE, canonical_root};

#[cfg(test)]
mod tests {
    use super::{
        BindError, GearwitPaths, KnownArm, LinkError, LinkSession, LinkTable, SOCKET_FILE,
        admit_attach, drop_session, serve_attach, wait_disconnect,
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

    fn attach_waiter_id(waiter_id: &str) -> WaiterLink {
        let mut message = fixture_attach();
        if let WaiterLink::AttachWaiter { waiter_id: id, .. } = &mut message {
            *id = waiter_id.to_owned();
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
    fn same_key_different_body_is_conflict() {
        let instant = now();
        let mut table = LinkTable::default();
        admit_attach(&mut table, fixture_attach(), instant, &[arm(instant)]).expect("admit");
        let error = admit_attach(
            &mut table,
            attach_waiter_id("01J00000000000000000000077"),
            instant,
            &[arm(instant)],
        )
        .expect_err("conflict");
        assert!(matches!(
            error,
            gearwit_protocol::WaiterLinkError::Semantic("request_id conflict")
        ));
    }

    #[test]
    fn expired_lease_replays_same_admission() {
        let instant = now();
        let mut table = LinkTable::default();
        let first =
            admit_attach(&mut table, fixture_attach(), instant, &[arm(instant)]).expect("first");
        let later = instant + TimeDuration::minutes(11);
        let second =
            admit_attach(&mut table, fixture_attach(), later, &[arm(later)]).expect("replay");
        assert_eq!(first, second);
        assert!(table.current().is_none());
        let successor = admit_attach(
            &mut table,
            attach_with("01J00000000000000000000098"),
            later,
            &[arm(later)],
        )
        .expect("successor");
        assert_ne!(first, successor);
        assert!(table.current().is_some());
    }

    #[test]
    fn conflict_is_detected_before_arm_checks() {
        let instant = now();
        let mut table = LinkTable::default();
        let unknown = admit_attach(&mut table, fixture_attach(), instant, &[]).expect("unknown");
        assert!(matches!(
            unknown,
            WaiterLink::AttachRejected { code, .. } if code == "unknown_arm"
        ));
        let error = admit_attach(
            &mut table,
            attach_waiter_id("01J00000000000000000000077"),
            instant,
            &[arm(instant)],
        )
        .expect_err("conflict");
        assert!(matches!(
            error,
            gearwit_protocol::WaiterLinkError::Semantic("request_id conflict")
        ));
    }

    #[test]
    fn drop_session_does_not_revoke_successor() {
        let instant = now();
        let mut table = LinkTable::default();
        admit_attach(&mut table, fixture_attach(), instant, &[arm(instant)]).expect("first");
        let current = table.current().expect("current");
        let old = LinkSession {
            link_id: current.link_id.clone(),
            arm_id: current.arm_id.clone(),
            generation: current.generation,
        };
        table.drop_current();
        admit_attach(
            &mut table,
            attach_with("01J00000000000000000000098"),
            instant,
            &[arm(instant)],
        )
        .expect("successor");
        let successor = table.current().expect("successor").link_id.clone();
        drop_session(&mut table, &old);
        assert_eq!(table.current().expect("still live").link_id, successor);
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
        let rejected = admit_attach(
            &mut table,
            attach_with("01J00000000000000000000097"),
            instant,
            &[stale],
        )
        .expect("stale");
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
    fn waiter_frames_use_command_cap_and_timeouts() {
        let config = super::waiter_frame_config();
        assert_eq!(config.max_payload_size, MAX_PAYLOAD);
        assert_eq!(config.read_timeout, Some(Duration::from_secs(5)));
        assert_eq!(config.write_timeout, Some(Duration::from_secs(5)));
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
    fn concurrent_bind_has_one_winner() {
        if let Ok(root) = std::env::var("GEARWIT_TEST_BIND_ROOT") {
            let paths = GearwitPaths::from_root(PathBuf::from(root)).expect("paths");
            match paths.bind() {
                Ok(listener) => {
                    thread::sleep(Duration::from_millis(800));
                    drop(listener);
                    std::process::exit(0);
                }
                Err(_) => std::process::exit(2),
            }
        }
        let exe = std::env::current_exe().expect("exe");
        for round in 0..5 {
            let root = temp_root();
            let paths = GearwitPaths::from_root(root.clone()).expect("layout");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let spawn = |paths: GearwitPaths, barrier: std::sync::Arc<std::sync::Barrier>| {
                thread::spawn(move || {
                    barrier.wait();
                    paths.bind()
                })
            };
            let a = spawn(paths.clone(), barrier.clone());
            let b = spawn(paths, barrier);
            let a = a.join().expect("thread a");
            let b = b.join().expect("thread b");
            let thread_wins = usize::from(a.is_ok()) + usize::from(b.is_ok());
            assert_eq!(thread_wins, 1, "thread round {round}");
            drop(a.ok());
            drop(b.ok());
            let _ = std::fs::remove_dir_all(&root);
        }
        for round in 0..5 {
            let root = temp_root();
            GearwitPaths::from_root(root.clone()).expect("layout");
            let spawn_child = |exe: PathBuf, root: PathBuf| {
                thread::spawn(move || {
                    std::process::Command::new(exe)
                        .args(["--exact", "tests::concurrent_bind_has_one_winner"])
                        .env("GEARWIT_TEST_BIND_ROOT", root)
                        .status()
                        .expect("child")
                })
            };
            let a = spawn_child(exe.clone(), root.clone());
            let b = spawn_child(exe.clone(), root.clone());
            let a = a.join().expect("a");
            let b = b.join().expect("b");
            let wins = usize::from(a.success()) + usize::from(b.success());
            assert_eq!(wins, 1, "round {round} codes {a:?} {b:?}");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn write_failure_does_not_commit() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let instant = now();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let stream = listener.accept().expect("accept");
            let mut table = LinkTable::default();
            let result = serve_attach(stream, &mut table, instant, &[arm(instant)]);
            tx.send((result.is_err(), table.current().is_none()))
                .expect("send");
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = UnixDomainSocket::connect(&socket).expect("connect");
        let payload = encode_payload(&fixture_attach()).expect("payload");
        client
            .write_all(&ipc_frame(COMMAND, &payload))
            .expect("write");
        drop(client);
        let (failed, empty) = rx.recv_timeout(Duration::from_secs(2)).expect("served");
        assert!(failed);
        assert!(empty);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn disconnect_revokes_then_successor_attaches() {
        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        let listener = paths.bind().expect("bind");
        let socket = paths.socket_path();
        let instant = now();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut table = LinkTable::default();
            let first = listener.accept().expect("accept");
            let mut served =
                serve_attach(first, &mut table, instant, &[arm(instant)]).expect("first");
            let session = served.session.expect("session");
            wait_disconnect(&mut served.reader).expect("eof");
            drop_session(&mut table, &session);
            let second = listener.accept().expect("second accept");
            let served =
                serve_attach(second, &mut table, instant, &[arm(instant)]).expect("second");
            tx.send(served.reply).expect("send");
        });
        thread::sleep(Duration::from_millis(20));
        let mut first = UnixDomainSocket::connect(&socket).expect("first");
        first
            .write_all(&ipc_frame(
                COMMAND,
                &encode_payload(&fixture_attach()).expect("p"),
            ))
            .expect("write");
        let mut reader = FrameReader::with_config(first, super::waiter_frame_config());
        let _ = reader.read_frame().expect("accepted");
        drop(reader);
        thread::sleep(Duration::from_millis(20));
        let mut second = UnixDomainSocket::connect(&socket).expect("second");
        second
            .write_all(&ipc_frame(
                COMMAND,
                &encode_payload(&attach_with("01J00000000000000000000098")).expect("p"),
            ))
            .expect("write");
        let mut reader = FrameReader::with_config(second, super::waiter_frame_config());
        let frame = reader.read_frame().expect("reply");
        let reply = decode_payload(&frame.payload).expect("decode");
        assert!(matches!(reply, WaiterLink::AttachAccepted { .. }));
        let served = rx.recv_timeout(Duration::from_secs(2)).expect("served");
        assert!(matches!(served, WaiterLink::AttachAccepted { .. }));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn user_home_and_symlink_components_are_checked() {
        let home = temp_root();
        std::fs::create_dir(&home).expect("home");
        let paths = GearwitPaths::from_user_home(&home).expect("home");
        assert_eq!(mode(paths.root()), 0o700);
        assert_eq!(mode(&paths.root().join("run")), 0o700);

        let linked = temp_root();
        std::fs::create_dir(&linked).expect("linked home");
        let real_lanyte = linked.join("real-lanyte");
        std::fs::create_dir(&real_lanyte).expect("real");
        std::os::unix::fs::symlink(&real_lanyte, linked.join(".lanyte")).expect("symlink");
        assert!(matches!(
            GearwitPaths::from_user_home(&linked),
            Err(BindError::Symlink(_))
        ));

        let root = temp_root();
        let paths = GearwitPaths::from_root(root.clone()).expect("root");
        let run = root.join("run");
        std::fs::remove_dir_all(&run).expect("remove run");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &run).expect("run link");
        assert!(matches!(
            GearwitPaths::from_root(root.clone()),
            Err(BindError::Symlink(_))
        ));
        drop(paths);

        let sock_root = temp_root();
        let paths = GearwitPaths::from_root(sock_root.clone()).expect("root");
        let target = sock_root.join("target");
        std::fs::create_dir(&target).expect("target");
        std::os::unix::fs::symlink(&target, paths.socket_path()).expect("sock link");
        assert!(matches!(paths.bind(), Err(BindError::Symlink(_))));
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&linked);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&sock_root);
    }

    #[test]
    fn owned_broad_mode_is_tightened() {
        let root = temp_root();
        std::fs::create_dir(&root).expect("root");
        let mut permissions = std::fs::metadata(&root).expect("meta").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&root, permissions).expect("chmod");
        let paths = GearwitPaths::from_root(root.clone()).expect("paths");
        assert_eq!(mode(paths.root()), 0o700);
        let _ = std::fs::remove_dir_all(&root);
    }
}
