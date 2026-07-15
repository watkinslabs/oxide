use super::*;
use alloc::string::String;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};

struct WakeCounter {
    hits: AtomicU32,
}

impl WakeCounter {
    fn new() -> Arc<Self> {
        Arc::new(Self { hits: AtomicU32::new(0) })
    }
}

impl vfs::EpollNotify for WakeCounter {
    fn notify(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
}

fn hits(c: &Arc<WakeCounter>) -> u32 {
    c.hits.load(Ordering::Relaxed)
}

fn wake_ref(c: &Arc<WakeCounter>) -> Weak<dyn vfs::EpollNotify> {
    Arc::downgrade(&(c.clone() as Arc<dyn vfs::EpollNotify>))
}

#[test]
fn abstract_and_literal_at_paths_are_distinct() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();

    registry.bind(String::from("\0svc")).unwrap();
    registry.bind(String::from("@svc")).unwrap();

    assert!(registry.lookup_listener("\0svc").is_some());
    assert!(registry.lookup_listener("@svc").is_some());
    assert_eq!(registry.snapshot_paths().len(), 2);
}

#[test]
fn abstract_path_display_uses_procfs_at_prefix() {
    let _serial = test_guard();
    assert!(unix_path_is_abstract("\0svc"));
    assert!(!unix_path_is_abstract("@svc"));
    assert_eq!(unix_path_display("\0svc"), b"@svc".to_vec());
    assert_eq!(unix_path_display("@svc"), b"@svc".to_vec());
}

#[test]
fn stream_bind_reserves_before_listen() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let addr = UnixAddr::from_sockaddr_path(b"\0bound-client".to_vec());
    let listener = registry.bind_addr(addr.clone()).unwrap();

    assert!(registry.is_bound_addr(&addr), "bind reserves the address");
    assert!(matches!(registry.connect_addr(&addr), Err(UnixConnectError::Refused)), "bind alone is not listening");

    listener.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
    assert!(registry.connect_addr(&addr).is_ok(), "listen publishes the endpoint");
}

#[test]
fn abstract_names_are_byte_identity_not_utf8_strings() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let raw = b"\0svc\xff".to_vec();
    let addr = UnixAddr::from_sockaddr_path(raw.clone());

    let listener = registry.bind_addr(addr.clone()).unwrap();
    listener.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);

    assert!(registry.lookup_listener_addr(&addr).is_some());
    assert_eq!(unix_path_display(raw), b"@svc\xff".to_vec());
}

#[test]
fn udev_control_path_connect_wakes_accept_and_round_trips() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let listener = registry.bind(String::from("/run/udev/control")).unwrap();
    listener.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
    let subs = Arc::new(vfs::PollSubscribers::new());
    let waiter = WakeCounter::new();
    subs.subscribe(1, wake_ref(&waiter));
    listener.register_subs(&subs);

    let client = registry.connect("/run/udev/control").expect("connect to udev control");
    assert_eq!(hits(&waiter), 1, "connect must wake the accepting server");
    assert_eq!(listener.pending_len(), 1);

    let (server, _pin) = listener.accept().expect("accepted pair");
    assert!(Arc::ptr_eq(&server, &client));
    assert_eq!(server.local_path(UnixEnd::A).as_deref(), Some(&b"/run/udev/control"[..]));
    assert_eq!(client.peer_path(UnixEnd::B).as_deref(), Some(&b"/run/udev/control"[..]));

    assert_eq!(client.write(UnixEnd::B, b"reload").unwrap(), 6);
    assert_eq!(server.read(UnixEnd::A, 64), b"reload".to_vec());
    assert_eq!(server.write(UnixEnd::A, b"ok").unwrap(), 2);
    assert_eq!(client.read(UnixEnd::B, 64), b"ok".to_vec());
}

#[test]
fn listener_readiness_tracks_accept_queue_only() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let listener = registry.bind(String::from("\0listener-poll")).unwrap();
    listener.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
    let subs = Arc::new(vfs::PollSubscribers::new());
    let readable = WakeCounter::new();
    let writable = WakeCounter::new();
    subs.subscribe_mask(1, wake_ref(&readable), vfs::POLL_IN);
    subs.subscribe_mask(2, wake_ref(&writable), vfs::POLL_OUT);
    listener.register_subs(&subs);
    assert_eq!(listener.poll_mask(), 0, "empty listener is not writable or readable");

    let client = registry.connect("\0listener-poll").expect("queued client");
    assert_eq!(hits(&readable), 1, "connection arrival wakes readable interest");
    assert_eq!(hits(&writable), 0, "connection arrival is not a writable edge");
    assert_eq!(listener.poll_mask(), vfs::POLL_IN, "queued connection makes accept readable");
    let (accepted, _pin) = listener.accept().expect("accept queued client");
    assert!(Arc::ptr_eq(&accepted, &client));
    assert_eq!(listener.poll_mask(), 0, "draining accept queue clears readiness");
}

#[test]
fn pathname_registry_key_is_inode_identity_not_display_path() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let a = UnixAddr {
        key: UnixAddrKey::Path { fsid: 1, ino: 10 },
        display: b"/run/a.sock".to_vec(),
    };
    let b = UnixAddr {
        key: UnixAddrKey::Path { fsid: 1, ino: 11 },
        display: b"/run/a.sock".to_vec(),
    };

    registry.bind_addr(a.clone()).unwrap().listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
    registry.bind_addr(b.clone()).unwrap().listen(128, crate::sysctl::DEFAULT_SOMAXCONN);

    assert!(registry.connect_addr(&a).is_ok());
    assert!(registry.connect_addr(&b).is_ok());
    assert_eq!(registry.snapshot_paths().len(), 2);
}

#[test]
fn symlinked_pathname_connect_hits_same_inode_key() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let bound = UnixAddr {
        key: UnixAddrKey::Path { fsid: 2, ino: 20 },
        display: b"/run/systemd/journal/dev-log".to_vec(),
    };
    let via_link = UnixAddr {
        key: UnixAddrKey::Path { fsid: 2, ino: 20 },
        display: b"/dev/log".to_vec(),
    };

    registry.bind_addr(bound).unwrap().listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
    let pair = registry.connect_addr(&via_link).expect("same inode key must connect");

    assert_eq!(pair.peer_path(UnixEnd::B).as_deref(), Some(&b"/run/systemd/journal/dev-log"[..]));
    assert!(registry.bind_addr(via_link).is_err(), "same socket inode key is busy");
}

#[test]
fn pathname_addr_preserves_non_utf8_display_bytes() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let ino: vfs::InodeRef = vfs::InodeBuilder::new(
        0x5150,
        vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(),
        vfs::default_file_ops(),
    ).build();
    let raw = b"/run/raw-\xff.sock".to_vec();
    let addr = UnixAddr::from_inode_bytes(raw.clone(), &ino);

    registry.bind_addr(addr.clone()).unwrap().listen(128, crate::sysctl::DEFAULT_SOMAXCONN);

    let pair = registry.connect_addr(&addr).expect("raw pathname socket address must connect");
    assert_eq!(pair.peer_path(UnixEnd::B).as_deref(), Some(&raw[..]));
    assert!(matches!(addr.key, UnixAddrKey::Path { fsid, ino: got } if fsid == ino.fsid() && got == ino.ino() as u64));
}


