use super::*;
use super::super::gc_test_support::{cancel_reserved_collection,
    arm_running_observer, collect_reserved_with_pause_after_pass, prepare_pause_after_pass,
    mark_pending_request, pending_request_was_marked, release_paused_pass,
    reserve_collection, RunningObserverRelease, unwind_reserved_after_pause,
    wait_pass_paused};

use alloc::sync::Arc;

struct PausedCollector {
    owner: Option<std::thread::JoinHandle<()>>,
    expect_unwind: bool,
}

impl PausedCollector {
    fn new() -> Self {
        Self::spawn(collect_reserved_with_pause_after_pass, false)
    }

    fn spawn(run: fn(), expect_unwind: bool) -> Self {
        prepare_pause_after_pass();
        assert!(reserve_collection(), "reserve deterministic collector owner");
        let owner = std::thread::Builder::new()
            .name("scm-gc-owner".into())
            .spawn(run);
        match owner {
            Ok(owner) => Self { owner: Some(owner), expect_unwind },
            Err(_) => {
                cancel_reserved_collection();
                panic!("spawn deterministic collector owner");
            }
        }
    }

    fn finish(&mut self) -> std::thread::Result<()> {
        release_paused_pass();
        match self.owner.take() { Some(owner) => owner.join(), None => Ok(()) }
    }
}

impl Drop for PausedCollector {
    fn drop(&mut self) {
        let failed = self.finish().is_err();
        if failed && !self.expect_unwind && !std::thread::panicking() {
            panic!("collector owner unwound unexpectedly");
        }
    }
}

fn bound(pair: &Arc<UnixPair>, end: UnixEnd) -> Arc<vfs::File> {
    let file = anon_file();
    register_file(&file, &pair.gc_node(end));
    file
}

fn socket_file(kind: crate::sock::SockKind, receiver: &GcNode) -> (Arc<vfs::File>, Arc<crate::sock::InetSocket>) {
    let socket = Arc::new(crate::sock::InetSocket::new_unix());
    *socket.kind.lock() = kind;
    let inode = crate::sock::make_inet_socket_inode(socket.clone());
    let dentry = vfs::Dentry::new(None, "socket".into(), inode.clone());
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
    register_file(&file, receiver);
    (file, socket)
}

fn self_cycle() -> (Arc<UnixPair>, Arc<vfs::File>, alloc::sync::Weak<vfs::File>, Arc<crate::sock::InetSocket>) {
    let pair = UnixPair::new();
    let (file, socket) = socket_file(crate::sock::SockKind::Unix(pair.clone(), UnixEnd::A),
        &pair.gc_node(UnixEnd::A));
    let weak = Arc::downgrade(&file);
    pair.write_with_rights(UnixEnd::B, b"cycle", classify_files(alloc::vec![file.clone()])).unwrap();
    (pair, file, weak, socket)
}

#[test]
fn self_cycle_is_collected() {
    let _guard = test_guard();
    let pair = UnixPair::new();
    let file = bound(&pair, UnixEnd::A);
    let weak = Arc::downgrade(&file);
    let rights = classify_files(alloc::vec![file.clone()]);
    pair.write_with_rights(UnixEnd::B, b"self", rights).unwrap();
    drop(file);

    collect_scm_rights();

    assert!(weak.upgrade().is_none(), "sole self-reference is reclaimed");
    let (payload, fds, _) = pair.read_stream(UnixEnd::A, 16);
    assert_eq!(payload, b"self");
    assert!(fds.is_empty(), "payload survives after its complete rights batch is detached");
}

#[test]
fn cross_socket_scc_is_collected() {
    let _guard = test_guard();
    let a = UnixPair::new();
    let b = UnixPair::new();
    let fa = bound(&a, UnixEnd::A);
    let fb = bound(&b, UnixEnd::A);
    let wa = Arc::downgrade(&fa);
    let wb = Arc::downgrade(&fb);
    a.write_with_rights(UnixEnd::B, b"a", classify_files(alloc::vec![fb.clone()])).unwrap();
    b.write_with_rights(UnixEnd::B, b"b", classify_files(alloc::vec![fa.clone()])).unwrap();
    drop(fa);
    drop(fb);

    collect_scm_rights();

    assert!(wa.upgrade().is_none() && wb.upgrade().is_none(), "unrooted SCC is reclaimed");
    assert!(a.read_stream(UnixEnd::A, 8).1.is_empty());
    assert!(b.read_stream(UnixEnd::A, 8).1.is_empty());
}

#[test]
fn pending_collector_request_runs_second_pass() {
    let _guard = test_guard();
    let a = UnixPair::new();
    let b = UnixPair::new();
    let fa = bound(&a, UnixEnd::A);
    let fb = bound(&b, UnixEnd::A);
    let wa = Arc::downgrade(&fa);
    let wb = Arc::downgrade(&fb);
    a.write_with_rights(UnixEnd::B, b"a", classify_files(alloc::vec![fb.clone()])).unwrap();
    b.write_with_rights(UnixEnd::B, b"b", classify_files(alloc::vec![fa.clone()])).unwrap();
    drop(fa);
    drop(fb);

    let mut owner = PausedCollector::new();
    if !wait_pass_paused() { panic!("collector owner did not reach post-pass handoff"); }
    assert!(wa.upgrade().is_none() && wb.upgrade().is_none(), "first pass reclaims first SCC");

    let c = UnixPair::new();
    let file = bound(&c, UnixEnd::A);
    let weak = Arc::downgrade(&file);
    c.write_with_rights(UnixEnd::B, b"c", classify_files(alloc::vec![file.clone()])).unwrap();
    drop(file);

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let requester = std::thread::spawn(move || {
        mark_pending_request();
        collect_scm_rights();
        done_tx.send(pending_request_was_marked()).expect("publish pending request completion");
    });
    let requested = done_rx.recv_timeout(std::time::Duration::from_secs(5));
    owner.finish().expect("collector owner");
    requester.join().expect("pending collector requester");

    assert_eq!(requested, Ok(true), "named requester publishes pending without waiting for owner");
    assert!(weak.upgrade().is_none(), "pending handoff runs a second collection pass");
    assert!(c.read_stream(UnixEnd::A, 8).1.is_empty());
}

#[test]
fn requester_retries_when_owner_reaches_idle_after_running_load() {
    let _guard = test_guard();
    let mut owner = PausedCollector::new();
    assert!(wait_pass_paused(), "collector owner reaches pre-idle handoff");

    let pair = UnixPair::new();
    let file = bound(&pair, UnixEnd::A);
    let weak = Arc::downgrade(&file);
    pair.write_with_rights(UnixEnd::B, b"race", classify_files(alloc::vec![file.clone()])).unwrap();
    drop(file);

    let mut observer = RunningObserverRelease::new();
    let requester_observer = observer.requester();
    let requester = std::thread::spawn(move || {
        arm_running_observer(&requester_observer);
        collect_scm_rights();
        requester_observer.idle_acquire_was_marked()
    });
    assert!(observer.wait_observed(), "requester loads running owner state");
    owner.finish().expect("collector owner reaches idle");
    observer.release();
    assert!(requester.join().expect("requester retries stale collector transition"),
        "requester acquires ownership after its stale CAS fails");

    assert!(weak.upgrade().is_none(), "retrying requester collects the cycle");
}

#[test]
fn running_observer_guard_releases_requester_during_unwind() {
    let _guard = test_guard();
    let mut owner = PausedCollector::new();
    assert!(wait_pass_paused(), "collector owner reaches pre-idle handoff");
    let observer = RunningObserverRelease::new();
    let requester_observer = observer.requester();
    let requester = std::thread::spawn(move || {
        arm_running_observer(&requester_observer);
        collect_scm_rights();
    });
    assert!(observer.wait_observed(), "requester pauses after loading running state");

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _observer = observer;
        panic!("inject observer-owner unwind");
    }));

    assert!(unwound.is_err());
    requester.join().expect("RAII release unblocks stale-state requester");
    owner.finish().expect("collector owner consumes the published request");
}

#[test]
fn newer_observer_cannot_reblock_released_generation() {
    let _guard = test_guard();
    let mut owner = PausedCollector::new();
    assert!(wait_pass_paused(), "collector owner reaches pre-idle handoff");
    let old = RunningObserverRelease::new();
    let requester_observer = old.requester();
    let waiter = requester_observer.clone();
    drop(old);
    let _newer = RunningObserverRelease::new();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let requester = std::thread::spawn(move || {
        arm_running_observer(&requester_observer);
        collect_scm_rights();
        done_tx.send(()).expect("publish released observer completion");
    });
    assert!(waiter.wait_observed(), "requester loads running owner state");
    assert_eq!(done_rx.recv_timeout(std::time::Duration::from_secs(5)), Ok(()),
        "new observer generation cannot erase an older release");
    owner.finish().expect("collector owner consumes the published request");
    requester.join().expect("released generation requester");
}

#[test]
fn overlapping_running_observers_release_exact_requester() {
    let _guard = test_guard();
    let mut owner = PausedCollector::new();
    assert!(wait_pass_paused(), "collector owner reaches pre-idle handoff");
    let mut first = RunningObserverRelease::new();
    let mut second = RunningObserverRelease::new();
    let first_requester = first.requester();
    let second_requester = second.requester();
    let first_waiter = first_requester.clone();
    let second_waiter = second_requester.clone();
    let (first_tx, first_rx) = std::sync::mpsc::channel();
    let (second_tx, second_rx) = std::sync::mpsc::channel();
    let first_thread = std::thread::spawn(move || {
        arm_running_observer(&first_requester);
        collect_scm_rights();
        first_tx.send(()).expect("publish first observer completion");
    });
    let second_thread = std::thread::spawn(move || {
        arm_running_observer(&second_requester);
        collect_scm_rights();
        second_tx.send(()).expect("publish second observer completion");
    });
    assert!(first_waiter.wait_observed() && second_waiter.wait_observed(),
        "both requesters load running owner state");
    second.release();
    assert_eq!(second_rx.recv_timeout(std::time::Duration::from_secs(5)), Ok(()));
    assert!(!first_waiter.is_released(),
        "releasing second observer cannot release first");
    first.release();
    first_rx.recv_timeout(std::time::Duration::from_secs(5)).expect("first observer completion");
    owner.finish().expect("collector owner consumes the published request");
    first_thread.join().expect("first observer requester");
    second_thread.join().expect("second observer requester");
}

#[test]
fn unwinding_collector_owner_restores_collection() {
    let _guard = test_guard();
    let owner = PausedCollector::spawn(unwind_reserved_after_pause, true);
    assert!(wait_pass_paused(), "collector owner reaches injected unwind handoff");
    drop(owner);

    let pair = UnixPair::new();
    let file = bound(&pair, UnixEnd::A);
    let weak = Arc::downgrade(&file);
    pair.write_with_rights(UnixEnd::B, b"cycle", classify_files(alloc::vec![file.clone()])).unwrap();
    drop(file);
    collect_scm_rights();

    assert!(weak.upgrade().is_none(), "later collector acquires ownership after worker unwind");
}

#[test]
fn paused_collector_guard_restores_collection_on_drop() {
    let _guard = test_guard();
    let owner = PausedCollector::new();
    assert!(wait_pass_paused(), "collector owner reaches post-pass handoff");
    drop(owner);

    let pair = UnixPair::new();
    let file = bound(&pair, UnixEnd::A);
    let weak = Arc::downgrade(&file);
    pair.write_with_rights(UnixEnd::B, b"cycle", classify_files(alloc::vec![file.clone()])).unwrap();
    drop(file);
    collect_scm_rights();

    assert!(weak.upgrade().is_none(), "guard drop leaves collector idle for later passes");
}

#[test]
fn external_root_preserves_entire_cross_socket_scc() {
    let _guard = test_guard();
    let a = UnixPair::new();
    let b = UnixPair::new();
    let fa = bound(&a, UnixEnd::A);
    let fb = bound(&b, UnixEnd::A);
    a.write_with_rights(UnixEnd::B, b"a", classify_files(alloc::vec![fb.clone()])).unwrap();
    b.write_with_rights(UnixEnd::B, b"b", classify_files(alloc::vec![fa.clone()])).unwrap();
    drop(fb);

    collect_scm_rights();

    let got_b = a.read_stream(UnixEnd::A, 8).1;
    let got_a = b.read_stream(UnixEnd::A, 8).1;
    assert_eq!(got_b.len(), 1);
    assert_eq!(got_a.len(), 1);
    assert!(Arc::ptr_eq(&got_a[0], &fa), "one external file root marks the complete SCC");
}

#[test]
fn duplicate_edges_count_multiplicity_and_mixed_batch_drops_whole() {
    let _guard = test_guard();
    let pair = UnixPair::new();
    let socket = bound(&pair, UnixEnd::A);
    let ordinary = anon_file();
    let ws = Arc::downgrade(&socket);
    let wo = Arc::downgrade(&ordinary);
    let rights = classify_files(alloc::vec![socket.clone(), socket.clone(), ordinary.clone()]);
    pair.write_with_rights(UnixEnd::B, b"mixed", rights).unwrap();
    drop(socket);
    drop(ordinary);

    collect_scm_rights();

    assert!(ws.upgrade().is_none(), "two queued copies are two in-flight references, not roots");
    assert!(wo.upgrade().is_none(), "collecting one socket edge drops its entire mixed rights batch");
    assert!(pair.read_stream(UnixEnd::A, 16).1.is_empty());
}

#[test]
fn discarding_last_reachable_edge_collects_new_garbage() {
    let _guard = test_guard();
    let root = UnixPair::new();
    let cycle = UnixPair::new();
    let root_file = bound(&root, UnixEnd::A);
    let cycle_file = bound(&cycle, UnixEnd::A);
    let weak = Arc::downgrade(&cycle_file);
    cycle.write_with_rights(UnixEnd::B, b"cycle", classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    root.write_with_rights(UnixEnd::B, b"edge", classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    collect_scm_rights();
    assert!(weak.upgrade().is_some(), "rooted incoming edge preserves the cycle");

    assert_eq!(root.read(UnixEnd::A, 8), b"edge");

    assert!(weak.upgrade().is_none(), "plain read drops the last root edge and runs collection");
    drop(root_file);
}

#[test]
fn pending_accept_pin_transfers_until_file_binding() {
    let _guard = test_guard();
    let registry = UnixRegistry::new();
    let listener = registry.bind("\0gc-pending".into()).unwrap();
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    let listener_file = anon_file();
    register_file(&listener_file, &listener.gc_node());
    let pair = registry.connect("\0gc-pending").unwrap();
    let file = bound(&pair, UnixEnd::A);
    let weak = Arc::downgrade(&file);
    pair.write_with_rights(UnixEnd::B, b"pending", classify_files(alloc::vec![file.clone()])).unwrap();
    drop(file);

    collect_scm_rights();
    assert!(weak.upgrade().is_some(), "listener queue pin roots the pending receiver");
    let (accepted, pin) = listener.accept().unwrap();
    assert!(Arc::ptr_eq(&accepted, &pair));
    collect_scm_rights();
    assert!(weak.upgrade().is_some(), "accept transfers the pin to its caller");

    drop(pin);
    collect_scm_rights();
    assert!(weak.upgrade().is_none(), "unbound accepted receiver becomes collectible after pin release");
    drop(listener_file);
}

#[test]
fn listener_pending_cycle_without_file_root_is_collected() {
    let _guard = test_guard();
    let registry = UnixRegistry::new();
    let listener = registry.bind("\0gc-listener-cycle".into()).unwrap();
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    let listener_file = anon_file();
    register_file(&listener_file, &listener.gc_node());
    let weak = Arc::downgrade(&listener_file);
    let pair = registry.connect("\0gc-listener-cycle").unwrap();
    pair.write_with_rights(UnixEnd::B, b"listener", classify_files(alloc::vec![listener_file.clone()])).unwrap();
    drop(listener_file);

    collect_scm_rights();

    assert!(weak.upgrade().is_none(), "listener-to-pending-endpoint ownership is a graph edge, not a root");
}

#[test]
fn stream_final_release_collects_cycle_unrooted_by_discard() {
    let _guard = test_guard();
    let root = UnixPair::new();
    let (root_file, root_socket) = socket_file(crate::sock::SockKind::Unix(root.clone(), UnixEnd::A),
        &root.gc_node(UnixEnd::A));
    let (_cycle, cycle_file, weak, cycle_socket) = self_cycle();
    root.write_with_rights(UnixEnd::B, b"root", classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    collect_scm_rights();
    assert!(weak.upgrade().is_some());

    drop(root_file);

    assert!(weak.upgrade().is_none(), "stream final release collects the newly unrooted cycle");
    assert!(root_socket.released.load(core::sync::atomic::Ordering::Acquire));
    assert!(cycle_socket.released.load(core::sync::atomic::Ordering::Acquire));
}

#[test]
fn unaccepted_abort_collects_cycle_unrooted_by_discard() {
    let _guard = test_guard();
    let registry = UnixRegistry::new();
    let listener = registry.bind("\0b855-listener".into()).unwrap();
    listener.listen(1, crate::sysctl::DEFAULT_SOMAXCONN);
    let socket = Arc::new(crate::sock::InetSocket::new_unix());
    *socket.kind.lock() = crate::sock::SockKind::UnixListener(listener.clone());
    *socket.unix_bound.lock() = Some(listener.clone());
    let inode = crate::sock::make_inet_socket_inode(socket.clone());
    let dentry = vfs::Dentry::new(None, "listener".into(), inode.clone());
    let listener_file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
    register_file(&listener_file, &listener.gc_node());
    let pending = registry.connect("\0b855-listener").unwrap();
    let (_cycle, cycle_file, weak, cycle_socket) = self_cycle();
    pending.write_with_rights(UnixEnd::B, b"root", classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    collect_scm_rights();
    assert!(weak.upgrade().is_some());

    drop(listener_file);

    assert!(weak.upgrade().is_none(), "unaccepted abort collects the newly unrooted cycle");
    assert!(socket.released.load(core::sync::atomic::Ordering::Acquire));
    assert!(cycle_socket.released.load(core::sync::atomic::Ordering::Acquire));
}

fn message_release_collects_cycle(kind: UnixMsgKind) {
    let root = match kind {
        UnixMsgKind::Datagram => UnixMsgPair::new_datagram(),
        UnixMsgKind::SeqPacket => UnixMsgPair::new(),
    };
    let (root_file, root_socket) = socket_file(
        crate::sock::SockKind::UnixMsgPair(root.clone(), UnixEnd::A), &root.gc_node(UnixEnd::A));
    let (_cycle, cycle_file, weak, cycle_socket) = self_cycle();
    root.send_with_rights(UnixEnd::B, b"root", classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    collect_scm_rights();
    assert!(weak.upgrade().is_some());

    drop(root_file);

    assert!(weak.upgrade().is_none(), "message final release collects the newly unrooted cycle");
    assert!(root_socket.released.load(core::sync::atomic::Ordering::Acquire));
    assert!(cycle_socket.released.load(core::sync::atomic::Ordering::Acquire));
}

#[test]
fn seqpacket_final_release_collects_cycle_unrooted_by_discard() {
    let _guard = test_guard();
    message_release_collects_cycle(UnixMsgKind::SeqPacket);
}

#[test]
fn datagram_pair_final_release_collects_cycle_unrooted_by_discard() {
    let _guard = test_guard();
    message_release_collects_cycle(UnixMsgKind::Datagram);
}

#[test]
fn datagram_queue_final_release_collects_cycle_unrooted_by_discard() {
    let _guard = test_guard();
    let root = UnixDgramQueue::new();
    let (root_file, root_socket) = socket_file(crate::sock::SockKind::UnixDgram(root.clone()),
        &root.gc_node());
    let (_cycle, cycle_file, weak, cycle_socket) = self_cycle();
    let message = UnixDgram { payload: b"root".to_vec(), creds: crate::unix_sock::MsgCred::from_ids((0, 0, 0)), fds: alloc::vec![] };
    root.try_push_with_rights(message, classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    collect_scm_rights();
    assert!(weak.upgrade().is_some());

    drop(root_file);

    assert!(weak.upgrade().is_none(), "datagram final release collects the newly unrooted cycle");
    assert!(root_socket.released.load(core::sync::atomic::Ordering::Acquire));
    assert!(cycle_socket.released.load(core::sync::atomic::Ordering::Acquire));
}
