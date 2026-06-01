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

// S3: cpu.max bandwidth decision (pure).
#[test]
fn cpu_bandwidth_throttles_over_quota() {
    use crate::{cpu_bandwidth_decision, CpuAction};
    // quota 50ms / period 100ms. base=0, period started at t=0.
    let (quota, period) = (50_000_000u64, 100_000_000u64);
    // consumed 20ms at t=30ms → under quota → Continue.
    assert_eq!(cpu_bandwidth_decision(20_000_000, 0, quota, period, 0, 30_000_000),
               CpuAction::Continue);
    // consumed 50ms at t=60ms → at quota → Throttle.
    assert_eq!(cpu_bandwidth_decision(50_000_000, 0, quota, period, 0, 60_000_000),
               CpuAction::Throttle);
    // t=100ms → period elapsed → Refill, re-baseline to current total.
    assert_eq!(cpu_bandwidth_decision(50_000_000, 0, quota, period, 0, 100_000_000),
               CpuAction::Refill { new_base_ns: 50_000_000 });
}

#[test]
fn cpu_bandwidth_consumed_is_delta_from_base() {
    use crate::{cpu_bandwidth_decision, CpuAction};
    let (quota, period) = (50_000_000u64, 100_000_000u64);
    // total 130ms but base 100ms → consumed 30ms < quota → Continue.
    assert_eq!(cpu_bandwidth_decision(130_000_000, 100_000_000, quota, period, 0, 40_000_000),
               CpuAction::Continue);
    // total 160ms, base 100ms → consumed 60ms ≥ quota → Throttle.
    assert_eq!(cpu_bandwidth_decision(160_000_000, 100_000_000, quota, period, 0, 40_000_000),
               CpuAction::Throttle);
}

#[test]
fn cpu_quota_groups_lists_only_capped() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+cpu").unwrap();
    let (capped, _) = t.create(ROOT, "capped").unwrap();
    let (free, _) = t.create(ROOT, "free").unwrap();
    t.add_proc(capped, 11);
    t.add_proc(free, 22);
    t.write_file(capped, "cpu.max", "50000 100000").unwrap();
    let groups = t.cpu_quota_groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].cgid, capped);
    assert_eq!(groups[0].quota_ns, 50_000_000);  // 50000us → ns
    assert_eq!(groups[0].period_ns, 100_000_000);
    assert_eq!(groups[0].pids, alloc::vec![11]);
}

// S2: cgroup cpu.weight maps to CFS load weight (100 ↔ nice-0 weight 1024).
#[test]
fn cpu_weight_maps_to_cfs() {
    use crate::cpu_weight_to_cfs;
    assert_eq!(cpu_weight_to_cfs(100), 1024); // default ↔ nice 0
    assert_eq!(cpu_weight_to_cfs(200), 2048); // 2× share
    assert_eq!(cpu_weight_to_cfs(50), 512);   // half share
    assert_eq!(cpu_weight_to_cfs(1), 10);     // min, ≥1
    assert!(cpu_weight_to_cfs(10000) > cpu_weight_to_cfs(100));
}

// K1b: memory controller actually charges + enforces memory.max.
#[test]
fn memory_max_enforced_and_charged() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (c, _) = t.create(ROOT, "svc").unwrap();
    t.add_proc(c, 100);
    t.write_file(c, "memory.max", "4096").unwrap();
    // Under the limit charges and shows up in memory.current.
    assert!(t.try_charge_mem(100, 4096));
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "4096\n");
    // One more byte over the cap is rejected; current unchanged.
    assert!(!t.try_charge_mem(100, 1));
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "4096\n");
    // Freeing some lets a smaller charge through.
    t.uncharge_mem(100, 4096);
    assert_eq!(t.charged(100), 0);
    assert!(t.try_charge_mem(100, 2048));
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "2048\n");
}

// memory.max with no limit set is unlimited; root has no controller.
#[test]
fn memory_unlimited_when_max_unset() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (c, _) = t.create(ROOT, "svc").unwrap();
    t.add_proc(c, 7);
    assert!(t.try_charge_mem(7, 1 << 30)); // 1 GiB, no cap
    assert_eq!(t.charged(7), 1 << 30);
}

// Hierarchy: an ancestor memory.max bounds the whole subtree even when
// the leaf has no limit of its own.
#[test]
fn memory_max_enforced_hierarchically() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (parent, _) = t.create(ROOT, "p").unwrap();
    t.write_subtree_control(parent, "+memory").unwrap();
    t.write_file(parent, "memory.max", "8192").unwrap();
    let (child, _) = t.create(parent, "c").unwrap();
    t.add_proc(child, 200);
    assert!(t.try_charge_mem(200, 8192));      // fills the ancestor cap
    assert!(!t.try_charge_mem(200, 1));         // ancestor cap blocks more
    // memory.current rolls up: parent reflects the child's charge.
    assert_eq!(s(&t.read_file(parent, "memory.current").unwrap()), "8192\n");
    assert_eq!(s(&t.read_file(child, "memory.current").unwrap()), "8192\n");
}

// Exit uncharges a process's entire footprint — symmetric by construction.
#[test]
fn exit_uncharges_whole_footprint() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (c, _) = t.create(ROOT, "svc").unwrap();
    t.add_proc(c, 100);
    t.write_file(c, "memory.max", "4096").unwrap();
    assert!(t.try_charge_mem(100, 1024));
    assert!(t.try_charge_mem(100, 2048));
    assert_eq!(t.charged(100), 3072);
    t.remove_proc(100); // process exit
    assert_eq!(t.charged(100), 0);
    assert_eq!(s(&t.read_file(c, "memory.current").unwrap()), "0\n");
}

// Moving a charged process migrates its charge to the destination node.
#[test]
fn move_migrates_memory_charge() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (a, _) = t.create(ROOT, "a").unwrap();
    let (b, _) = t.create(ROOT, "b").unwrap();
    t.add_proc(a, 50);
    assert!(t.try_charge_mem(50, 4096));
    assert_eq!(s(&t.read_file(a, "memory.current").unwrap()), "4096\n");
    t.add_proc(b, 50); // move 50 from a → b
    assert_eq!(s(&t.read_file(a, "memory.current").unwrap()), "0\n");
    assert_eq!(s(&t.read_file(b, "memory.current").unwrap()), "4096\n");
    assert_eq!(t.charged(50), 4096);
}
