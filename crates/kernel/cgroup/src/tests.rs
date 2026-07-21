// Hosted unit tests for the cgroup v2 hierarchy logic (`tree`). The
// VFS/devfs bridge is exercised by the in-guest boot smoke; here we
// pin the pure hierarchy + controller semantics per `26§4,§8`.

use crate::tree::*;
use alloc::string::ToString;

mod memory_accounting;

fn s(v: &[u8]) -> &str { core::str::from_utf8(v).unwrap() }

/// Converted fs_context path (D13/D14): `realize_tree` materialises the unified
/// hierarchy's `(CgroupFs, root CgDir)`; the test realizes the same explicit
/// `s_type`/`s_op`/`s_root` shape as `FsType::mount`/`vfs_get_tree` does at
/// `fsconfig(CMD_CREATE)`.
/// Pin the cgroup2 identity (magic + root CgDir ino + fsid) the SB realizes,
/// and that it is TARGET-INDEPENDENT (a second realize yields the same identity
/// — the singleton tree carries no mount-target state).
#[test]
fn realize_tree_builds_target_independent_cgroup2_sb() {
    use alloc::sync::Arc;
    use vfs::fs::{FileSystem, FsFlags, FsType};
    use vfs::{SimpleSuperOps, SuperBlock, SuperOps};
    use vfs::superblock::next_anon_dev;
    const CGROUP2_MAGIC: u64 = 0x6367_7270;
    const ROOT_CGDIR_INO: u64 = 0x6000_0000 + 1; // DIR_INO_BASE + tree::ROOT

    let (fs, root) = crate::realize_tree();
    assert_eq!(fs.magic(), CGROUP2_MAGIC, "CgroupFs.magic == CGROUP2_SUPER_MAGIC");
    assert_eq!(root.ino(), ROOT_CGDIR_INO, "root CgDir ino = DIR_INO_BASE + ROOT");
    assert_eq!(root.fsid(), CGROUP2_MAGIC, "root CgDir fsid == CGROUP2_FSID");
    assert!(crate::is_mounted(), "realize_tree marks the singleton hierarchy mounted");

    let fs_for_sb: Arc<dyn FileSystem> = fs;
    let s_op: Arc<dyn SuperOps> = Arc::new(SimpleSuperOps {
        magic: fs_for_sb.magic(),
        block_size: fs_for_sb.block_size(),
        options: fs_for_sb.show_options(),
    });
    let ty: Arc<dyn vfs::FileSystemType> =
        FsType::new("cgroup2", CGROUP2_MAGIC, FsFlags::empty(), alloc::boxed::Box::new(|_, _, _, _| unreachable!("test fs type is not mounted through ->mount")));
    let sb = SuperBlock::from_ops(ty, s_op, Some(root), CGROUP2_MAGIC, next_anon_dev(), fs_for_sb.block_size(), "cgroup2".to_string(), Arc::new(()));
    fs_for_sb.set_sb(Arc::downgrade(&sb)).expect("cgroup2 set_sb");
    assert_eq!(sb.s_magic, CGROUP2_MAGIC, "SB s_magic == CGROUP2_SUPER_MAGIC");
    let sroot = sb.s_root_inode().expect("SB has a root inode (d_make_root)");
    assert_eq!(sroot.ino(), ROOT_CGDIR_INO, "SB root inode = root CgDir");
    assert_eq!(sroot.fsid(), CGROUP2_MAGIC, "SB root inode fsid preserved through the SB build");

    // Target-independence: a second CMD_CREATE realize yields identical identity.
    let (fs2, root2) = crate::realize_tree();
    assert_eq!(fs2.magic(), CGROUP2_MAGIC);
    assert_eq!(root2.ino(), ROOT_CGDIR_INO);
    assert_eq!(root2.fsid(), CGROUP2_MAGIC);
}

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

// Inode-synthesis surface: node_files / has_file / child_id / child_names
// are what CgroupFs::lookup + CgDir::readdir resolve against (replacing the
// old devfs registry). Pin the EXACT file set for root vs a non-root child.
#[test]
fn node_files_and_children_drive_synthesis() {
    let mut t = Tree::new();
    t.mount_root();
    // Root: CORE_FILES only (no kill/freeze; root has no controller files
    // until subtree_control delegates — root's own avail is ALL but its
    // interface files are the controller files of ALL since avail==ALL).
    let rf = t.node_files(ROOT);
    for f in CORE_FILES { assert!(rf.contains(f), "root missing {f}"); }
    assert!(!rf.contains(&"cgroup.kill"));   // root has no kill/freeze
    assert!(!rf.contains(&"cgroup.freeze"));
    // root avail == ALL, so all controller files are present.
    assert!(rf.contains(&"pids.max"));
    assert!(rf.contains(&"cpu.max"));
    assert!(t.has_file(ROOT, "cgroup.procs"));
    assert!(!t.has_file(ROOT, "cgroup.kill"));

    // Non-root child with pids delegated: CORE + kill/freeze + pids files.
    t.write_subtree_control(ROOT, "+pids").unwrap();
    let (c, _) = t.create(ROOT, "svc").unwrap();
    assert_eq!(t.child_id(ROOT, "svc"), Some(c));
    assert_eq!(t.child_names(ROOT), alloc::vec!["svc".to_string()]);
    let cf = t.node_files(c);
    assert!(cf.contains(&"cgroup.kill"));    // non-root gets kill/freeze
    assert!(cf.contains(&"cgroup.freeze"));
    assert!(cf.contains(&"pids.max"));       // pids delegated
    assert!(!cf.contains(&"cpu.max"));        // cpu NOT delegated
    assert!(t.has_file(c, "pids.max"));
    assert!(!t.has_file(c, "cpu.max"));
    assert!(t.child_id(ROOT, "nope").is_none());
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
    // a has an online child; cgroup v2 reports EBUSY. Root is also busy.
    assert_eq!(t.remove(a), Err(vfs::VfsError::Ebusy));
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

// S4c: io.stat accounting — charge_io rolls up the subtree.
#[test]
fn io_stat_accounts_and_rolls_up() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+io").unwrap();
    let (a, _) = t.create(ROOT, "a").unwrap();
    let (b, _) = t.create(a, "b").unwrap();
    t.add_proc(a, 10);
    t.add_proc(b, 20);
    t.charge_io(10, 4096, false); // read on a
    t.charge_io(20, 8192, true);  // write on b (child)
    t.charge_io(20, 4096, false); // read on b
    // node a's own counters: just the read on pid 10.
    assert_eq!(t.subtree_io(b), (4096, 8192, 1, 1));
    // a's subtree = a's own + b's: rbytes 4096+4096, wbytes 8192.
    assert_eq!(t.subtree_io(a), (8192, 8192, 2, 1));
    // io.stat text reflects the subtree.
    assert_eq!(s(&t.read_file(a, "io.stat").unwrap()),
               "8:0 rbytes=8192 wbytes=8192 rios=2 wios=1\n");
    // empty cgroup → empty io.stat.
    let (c, _) = t.create(ROOT, "c").unwrap();
    assert_eq!(s(&t.read_file(c, "io.stat").unwrap()), "");
}

// S4b: cpuset.cpus cpulist → bitmask (pure).
#[test]
fn cpulist_parses_ranges_and_singles() {
    use crate::cpulist_to_mask;
    assert_eq!(cpulist_to_mask("0"), Some(0b1));
    assert_eq!(cpulist_to_mask("0-3"), Some(0b1111));
    assert_eq!(cpulist_to_mask("0-1,3"), Some(0b1011));
    assert_eq!(cpulist_to_mask("2,4,6"), Some(0b101_0100));
    assert_eq!(cpulist_to_mask(" 1 - 2 , 5 "), Some(0b10_0110)); // tolerant of spaces
    assert_eq!(cpulist_to_mask(""), None);     // empty → no restriction
    assert_eq!(cpulist_to_mask("  "), None);
    assert_eq!(cpulist_to_mask("63"), Some(1u64 << 63));
    assert_eq!(cpulist_to_mask("garbage"), None);
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

// Y1: cgroup delegation ownership. systemd (root) creates the delegated
// user@UID.service cgroup, then chowns the DIRECTORY + cgroup.procs/threads/
// subtree_control to the target uid — while the resource-control files
// (memory.max) STAY root so the user cannot raise its own top-level limit.
// Pin that the hierarchy PERSISTS the chown (was store-and-ignore on the
// synthesized inode) with that exact per-file boundary.
#[test]
fn delegation_owner_persists_with_resource_file_boundary() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (svc, _) = t.create(ROOT, "user@979.service").unwrap();
    // Root-created → dir + every file default root:root.
    assert_eq!(t.dir_owner(svc), (0, 0));
    assert_eq!(t.file_owner(svc, "cgroup.procs"), (0, 0));
    assert_eq!(t.file_owner(svc, "memory.max"), (0, 0));
    // systemd delegation: chown the dir + the 3 delegated files to 979.
    t.set_dir_owner(svc, 979, 979).unwrap();
    for f in ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"] {
        t.set_file_owner(svc, f, 979, 979).unwrap();
    }
    assert_eq!(t.dir_owner(svc), (979, 979), "delegated dir chown persists");
    assert_eq!(t.file_owner(svc, "cgroup.procs"), (979, 979), "delegated file chown persists");
    // NOT delegated → stays at the frozen creation owner (root).
    assert_eq!(t.file_owner(svc, "memory.max"), (0, 0), "memory.max stays root:root");
    // A sub-cgroup the delegated user creates is stamped with its fsuid → all
    // its files default user-owned (Linux `cgroup_create` uses current_fsuid).
    let (sub, _) = t.create(svc, "app.scope").unwrap();
    t.set_created_owner(sub, 979, 979);
    assert_eq!(t.dir_owner(sub), (979, 979));
    assert_eq!(t.file_owner(sub, "cgroup.procs"), (979, 979));
}

// systemd's `DelegateSubgroup=init.scope` recursively chowns every interface
// currently exposed in init.scope. Controllers can become visible only after
// that walk, when the user manager enables them in its parent. Those late files
// must retain the recursive delegation owner, while the partially delegated
// service boundary above remains root-owned for resource controls.
#[test]
fn recursive_delegation_owns_late_controller_files() {
    let mut t = Tree::new();
    t.mount_root();
    t.write_subtree_control(ROOT, "+memory").unwrap();
    let (svc, _) = t.create(ROOT, "user@979.service").unwrap();
    let (init, _) = t.create(svc, "init.scope").unwrap();

    t.set_dir_owner(init, 979, 979).unwrap();
    for file in t.node_files(init) {
        t.set_file_owner(init, file, 979, 979).unwrap();
    }
    t.write_subtree_control(svc, "+memory").unwrap();

    assert_eq!(t.file_owner(init, "memory.max"), (979, 979));
    assert_eq!(t.file_owner(svc, "memory.max"), (0, 0));
}

// Y1 end-to-end: the code=219/EXIT_CGROUP blocker. Cgroup inodes are
// synthesized root:root and the chown was LOST (ephemeral inode), so
// `systemd --user` (uid 979) got EACCES opening its delegated cgroup.procs.
// Drive the REAL path — synthesize the inode, chown THROUGH it (`set_owner`
// → OwnerPersist hook → hierarchy), re-synthesize — and assert uid 979 may
// now WRITE it.
#[test]
fn delegated_cgroup_procs_writable_by_uid_after_chown() {
    let _ = crate::realize_tree(); // mount the singleton hierarchy
    let svc = crate::mkdir_child(ROOT, "user@979.svc-e2e", 0, 0).unwrap();
    let mut u979 = vfs::Cred::root();
    u979.uid = 979; u979.gid = 979;
    u979.cap_dac_override = false; u979.cap_dac_read_search = false;
    u979.cap_chown = false; u979.cap_fowner = false; u979.cap_fsetid = false;
    // Root-created: cgroup.procs is root:root 0644 → uid 979 WRITE = EACCES.
    let before = crate::inode::make_cg_file(svc, "cgroup.procs");
    assert_eq!(before.uid(), Some(0));
    assert_eq!(vfs::inode_permission(&before, vfs::MAY_WRITE, &u979), Err(vfs::VfsError::Eacces));
    // systemd (root) chowns the delegated file to 979 — the write-through hook
    // must PERSIST to the hierarchy, not just the ephemeral inode.
    before.set_owner(979, 979).unwrap();
    assert_eq!(crate::node_file_owner(svc, "cgroup.procs"), (979, 979), "chown persisted to hierarchy");
    // A fresh lookup re-synthesizes the inode → owner 979, mode 0644 → uid 979
    // WRITE now permitted (owner class rw). code=219 blocker cleared.
    let after = crate::inode::make_cg_file(svc, "cgroup.procs");
    assert_eq!(after.uid(), Some(979));
    assert_eq!(vfs::inode_permission(&after, vfs::MAY_WRITE, &u979), Ok(()));
    // The delegated DIRECTORY is 0755 so once chowned to 979 the user may
    // create sub-cgroups (mkdir needs owner MAY_WRITE on the parent dir).
    crate::chown_dir(svc, 979, 979).unwrap();
    let dir = crate::inode::make_cg_dir(svc);
    assert_eq!(dir.uid(), Some(979));
    assert_eq!(vfs::inode_permission(&dir, vfs::MAY_WRITE, &u979), Ok(()));
}

#[test]
fn cgroup_control_file_truncate_zero_is_noop() {
    let _ = crate::realize_tree();
    let f = crate::inode::make_cg_file(ROOT, "cgroup.subtree_control");
    assert_eq!(f.truncate(0), Ok(()), "kernfs control-file O_TRUNC is admitted");
    assert_eq!(crate::write_file(ROOT, "cgroup.subtree_control", "+pids"), Ok(()));
}
