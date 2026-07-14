use super::*;

use alloc::sync::Arc;
use sync::{SocketTable, Spinlock};

static TEST_GC: Spinlock<(), SocketTable> = Spinlock::new(());

fn bound(pair: &Arc<UnixPair>, end: UnixEnd) -> Arc<vfs::File> {
    let file = anon_file();
    register_file(&file, &pair.gc_node(end));
    file
}

#[test]
fn self_cycle_is_collected() {
    let _serial = TEST_GC.lock();
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
    let _serial = TEST_GC.lock();
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
fn external_root_preserves_entire_cross_socket_scc() {
    let _serial = TEST_GC.lock();
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
    let _serial = TEST_GC.lock();
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
    let _serial = TEST_GC.lock();
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
    let _serial = TEST_GC.lock();
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
    let _serial = TEST_GC.lock();
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
