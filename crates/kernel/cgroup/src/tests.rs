// Hosted unit tests for the cgroup v2 hierarchy logic (`tree`). The
// VFS/devfs bridge is exercised by the in-guest boot smoke; here we
// pin the pure hierarchy + controller semantics per `26§4,§8`.

use crate::tree::*;

fn s(v: &[u8]) -> &str { core::str::from_utf8(v).unwrap() }

#[test]
fn root_mounts_with_all_controllers() {
    let mut t = Tree::new();
    assert!(t.mount_root());
    assert!(!t.mount_root()); // idempotent
    assert_eq!(s(&t.read_file(ROOT, "cgroup.controllers").unwrap()),
        "cpu cpuset io memory pids\n");
    assert_eq!(s(&t.read_file(ROOT, "cgroup.subtree_control").unwrap()), "\n");
    assert_eq!(t.path_of(ROOT), "/");
}

#[test]
fn subtree_control_gates_child_availability() {
    let mut t = Tree::new();
    t.mount_root();
    // No delegation yet → child sees no controllers.
    let (c0, avail0) = t.create(ROOT, "a").unwrap();
    assert_eq!(avail0, 0);
    assert!(controller_files(avail0).is_empty());
    assert!(t.read_file(c0, "pids.max").is_err());

    // Delegate pids+memory at root → next child gets those files.
    t.write_subtree_control(ROOT, "+pids +memory").unwrap();
    let (c1, avail1) = t.create(ROOT, "b").unwrap();
    assert_eq!(avail1, PIDS | MEMORY);
    assert!(controller_files(avail1).contains(&"pids.max"));
    assert!(controller_files(avail1).contains(&"memory.max"));
    assert!(!controller_files(avail1).contains(&"cpu.weight"));
    assert_eq!(s(&t.read_file(c1, "pids.max").unwrap()), "max\n");
}

#[test]
fn enabling_unavailable_controller_is_enospc() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+pids").unwrap();
    let (c, _) = t.create(ROOT, "leaf").unwrap();
    // child only has pids available; enabling cpu must fail ENOSPC.
    assert_eq!(t.write_subtree_control(c, "+cpu"), Err(vfs::VfsError::Enospc));
    // unknown controller → EINVAL.
    assert_eq!(t.write_subtree_control(c, "+bogus"), Err(vfs::VfsError::Einval));
}

#[test]
fn pids_limit_enforced_across_subtree() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+pids").unwrap();
    let (c, _) = t.create(ROOT, "svc").unwrap();
    t.write_file(c, "pids.max", "2").unwrap();
    assert_eq!(s(&t.read_file(c, "pids.max").unwrap()), "2\n");
    t.add_proc(c, 100);
    assert!(!t.fork_would_exceed_pids(c)); // 1 -> 2 ok
    t.add_proc(c, 101);
    assert!(t.fork_would_exceed_pids(c));  // 2 -> 3 exceeds
    t.remove_proc(101);
    assert!(!t.fork_would_exceed_pids(c));
}

// K1b: the pids controller counts THREADS too (not just process leaders).
#[test]
fn pids_limit_counts_threads() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+pids").unwrap();
    let (c, _) = t.create(ROOT, "svc").unwrap();
    t.write_file(c, "pids.max", "3").unwrap();
    t.add_proc(c, 200);              // leader → 1 task
    t.add_thread(200, 201);          // thread → 2 tasks
    assert!(!t.fork_would_exceed_pids(c)); // 2 -> 3 ok
    t.add_thread(200, 202);          // 3 tasks
    assert!(t.fork_would_exceed_pids(c));  // 3 -> 4 exceeds (threads counted)
    // pids.current reflects every task.
    assert_eq!(s(&t.read_file(c, "pids.current").unwrap()), "3\n");
    t.remove_thread(202);
    assert!(!t.fork_would_exceed_pids(c));
    assert_eq!(s(&t.read_file(c, "pids.current").unwrap()), "2\n");
}

#[test]
fn procs_attach_events_and_proc_path() {
    let mut t = Tree::new();
    t.mount_root();
    let (a, _) = t.create(ROOT, "a").unwrap();
    let (b, _) = t.create(a, "b").unwrap();
    assert_eq!(t.path_of(b), "/a/b");
    assert_eq!(s(&t.read_file(b, "cgroup.events").unwrap()), "populated 0\nfrozen 0\n");
    t.add_proc(b, 42);
    assert_eq!(s(&t.read_file(b, "cgroup.procs").unwrap()), "42\n");
    // ancestor sees subtree populated.
    assert_eq!(s(&t.read_file(a, "cgroup.events").unwrap()), "populated 1\nfrozen 0\n");
    assert_eq!(t.cgroup_of(42), b);
    // moving reassigns membership.
    t.add_proc(a, 42);
    assert_eq!(t.cgroup_of(42), a);
    assert_eq!(s(&t.read_file(b, "cgroup.procs").unwrap()), "");
}

#[test]
fn memory_and_cpu_limits_roundtrip() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory +cpu").unwrap();
    let (c, _) = t.create(ROOT, "g").unwrap();
    t.write_file(c, "memory.max", "1048576").unwrap();
    assert_eq!(s(&t.read_file(c, "memory.max").unwrap()), "1048576\n");
    t.write_file(c, "memory.max", "max").unwrap();
    assert_eq!(s(&t.read_file(c, "memory.max").unwrap()), "max\n");
    t.write_file(c, "cpu.weight", "200").unwrap();
    assert_eq!(s(&t.read_file(c, "cpu.weight").unwrap()), "200\n");
    assert_eq!(t.write_file(c, "cpu.weight", "0"), Err(vfs::VfsError::Einval));
    t.write_file(c, "cpu.max", "50000 100000").unwrap();
    assert_eq!(s(&t.read_file(c, "cpu.max").unwrap()), "50000 100000\n");
}

#[test]
fn freeze_and_remove_semantics() {
    let mut t = Tree::new();
    t.mount_root();
    let (a, _) = t.create(ROOT, "a").unwrap();
    let (b, _) = t.create(a, "b").unwrap();
    t.set_frozen(a, true);
    assert_eq!(s(&t.read_file(a, "cgroup.events").unwrap()), "populated 0\nfrozen 1\n");
    // a has a child → ENOTEMPTY; root → EBUSY.
    assert_eq!(t.remove(a), Err(vfs::VfsError::Enotempty));
    assert_eq!(t.remove(ROOT), Err(vfs::VfsError::Ebusy));
    assert!(t.remove(b).is_ok());
    assert!(t.remove(a).is_ok());
    assert!(t.resolve("a").is_none());
}

#[test]
fn kill_lists_all_subtree_pids() {
    let mut t = Tree::new();
    t.mount_root();
    let (a, _) = t.create(ROOT, "a").unwrap();
    let (b, _) = t.create(a, "b").unwrap();
    t.add_proc(a, 1);
    t.add_proc(b, 2);
    t.add_proc(b, 3);
    let mut pids = t.subtree_pids(a);
    pids.sort_unstable();
    assert_eq!(pids, alloc::vec![1, 2, 3]);
}
