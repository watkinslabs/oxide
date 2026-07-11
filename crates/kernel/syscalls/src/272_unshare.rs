// 272 unshare — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

const CLONE_NEWTIME:  u64 = 0x00000080;
const CLONE_VM:       u64 = 0x00000100;
const CLONE_FS:       u64 = 0x00000200;
const CLONE_FILES:    u64 = 0x00000400;
const CLONE_SIGHAND:  u64 = 0x00000800;
const CLONE_THREAD:   u64 = 0x00010000;
const CLONE_NEWNS:    u64 = 0x00020000;
const CLONE_SYSVSEM:  u64 = 0x00040000;
const UNSHARE_EMPTY_MNTNS: u64 = 0x00100000;
const CLONE_NEWCGROUP:u64 = 0x02000000;
const CLONE_NEWUTS:   u64 = 0x04000000;
const CLONE_NEWIPC:   u64 = 0x08000000;
const CLONE_NEWUSER:  u64 = 0x10000000;
const CLONE_NEWPID:   u64 = 0x20000000;
const CLONE_NEWNET:   u64 = 0x40000000;

const CLONE_NS_ALL: u64 = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC
    | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWTIME;
const UNSHARE_ALLOWED: u64 = CLONE_THREAD | CLONE_FS | CLONE_SIGHAND | CLONE_VM
    | CLONE_FILES | CLONE_SYSVSEM | CLONE_NS_ALL | UNSHARE_EMPTY_MNTNS;

#[inline]
fn ns_bit_for_clone(clone_flag: u64) -> Option<u32> {
    Some(match clone_flag {
        CLONE_NEWNS      => 0,
        CLONE_NEWUTS     => 1,
        CLONE_NEWIPC     => 2,
        CLONE_NEWUSER    => 3,
        CLONE_NEWPID     => 4,
        CLONE_NEWNET     => 5,
        CLONE_NEWCGROUP  => 6,
        _ => return None,
    })
}

/// Translate CLONE_NEW* flags into a namespace-bit mask (the `ns_membership`
/// bit layout). # C: O(1)
pub(crate) fn ns_bits_from_flags(flags: u64) -> u64 {
    let mut bits = 0u64;
    for clone_flag in [
        CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER,
        CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP,
    ] {
        if (flags & clone_flag) != 0 {
            if let Some(b) = ns_bit_for_clone(clone_flag) {
                bits |= 1u64 << b;
            }
        }
    }
    bits
}

/// `sys_unshare(flags)` — slot 272. Detach the calling task from
/// the named namespaces (Linux `ksys_unshare`). # C: O(1)
pub fn sys_unshare(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let mut flags = args.a0;
    if (flags & CLONE_NEWUSER) != 0 { flags |= CLONE_THREAD | CLONE_FS; }
    if (flags & CLONE_VM) != 0 { flags |= CLONE_SIGHAND; }
    if (flags & CLONE_SIGHAND) != 0 { flags |= CLONE_THREAD; }
    if (flags & UNSHARE_EMPTY_MNTNS) != 0 { flags |= CLONE_NEWNS; }
    if (flags & CLONE_NEWNS) != 0 { flags |= CLONE_FS; }
    if (flags & !UNSHARE_ALLOWED) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if (flags & CLONE_NEWTIME) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let bits = ns_bits_from_flags(flags);
    if bits == 0 { return 0; }
    cur.ns_membership.fetch_or(bits, Ordering::Release);
    apply_new_namespaces(cur, bits);
    0
}

/// Create fresh namespaces for `task` for each set bit in `bits` (the
/// `ns_membership` bit layout). Shared by `unshare(2)` (task = caller) and
/// `clone(2)`/fork (task = the new child, after it inherited the parent's
/// namespaces) so clone-time CLONE_NEW* creates new namespaces just like
/// Linux `create_new_namespaces`. Reads `task`'s current (inherited) ids as
/// the parent ids, then overwrites them. # C: O(snapshotted entries)
pub(crate) fn apply_new_namespaces(task: &sched::Task, bits: u64) {
    use core::sync::atomic::Ordering;
    if (bits & (1u64 << 1)) != 0 {
        // CLONE_NEWUTS — allocate a fresh shared uts_namespace seeded with a
        // COPY of the task's current ns names (UTS ns isolates both), then
        // point the task at it. Members of the new ns share the entry.
        let cur_ns = task.uts_ns.load(Ordering::Acquire);
        let host = crate::hostname::host_for(cur_ns);
        let dom = crate::hostname::dom_for(cur_ns);
        let new_id = nscg::uts_ns::uts_alloc(host, dom);
        task.uts_ns.store(new_id, Ordering::Release);
    }
    if (bits & (1u64 << 2)) != 0 {
        // CLONE_NEWIPC — fresh ipc_ns id (F100).
        static NEXT_IPC_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_IPC_NS.fetch_add(1, Ordering::AcqRel);
        task.ipc_ns.store(id, Ordering::Release);
    }
    if (bits & (1u64 << 5)) != 0 {
        // CLONE_NEWNET — fresh net_ns id (F101). B518: materialize the
        // ns's isolated view — a loopback-only interface (lo, 127.0.0.1/8);
        // its private AF_UNIX registry is created lazily on first bind.
        static NEXT_NET_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_NET_NS.fetch_add(1, Ordering::AcqRel);
        task.net_ns.store(id, Ordering::Release);
        net::net_ns::materialize_loopback(id);
    }
    if (bits & (1u64 << 4)) != 0 {
        // CLONE_NEWPID — pending bit; fork dispatcher allocates ns (F105).
        task.unshare_pid_pending.store(true, Ordering::Release);
    }
    if (bits & (1u64 << 3)) != 0 {
        // CLONE_NEWUSER — fresh user_ns id (F106 substrate).
        // F118: also record (new, parent) so has_cap_for can walk
        // ancestors per `27§R01`.
        static NEXT_USER_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let new_id = NEXT_USER_NS.fetch_add(1, Ordering::AcqRel);
        let parent = task.user_ns.load(Ordering::Acquire);
        nscg::proc_ns::user_ns_record(new_id, parent);
        task.parent_user_ns.store(parent, Ordering::Release);
        task.user_ns.store(new_id, Ordering::Release);
    }
    if (bits & (1u64 << 6)) != 0 {
        // CLONE_NEWCGROUP — fresh cgroup_ns id (F106 substrate).
        static NEXT_CGROUP_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_CGROUP_NS.fetch_add(1, Ordering::AcqRel);
        task.cgroup_ns.store(id, Ordering::Release);
    }
    if (bits & (1u64 << 0)) != 0 {
        // CLONE_NEWNS — fresh mount_ns id (F107 substrate) + snapshot
        // parent's NS-tagged mount entries into the new id (F119).
        static NEXT_MOUNT_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let new_id = NEXT_MOUNT_NS.fetch_add(1, Ordering::AcqRel);
        let parent_ns = task.mount_ns.load(Ordering::Acquire);
        devfs::snapshot_ns(parent_ns, new_id);
        // U2-b: copy the unified mount table's entries too, so the new ns
        // starts with a full private copy of the parent tree then diverges.
        let mount_map = vfs::mount::snapshot_ns_map(parent_ns, new_id);
        remap_task_fs_paths(task, &mount_map);
        task.mount_ns.store(new_id, Ordering::Release);
    }
}

fn remap_task_fs_paths(task: &sched::Task, mount_map: &[(u64, u64)]) {
    fn mapped(id: u64, mount_map: &[(u64, u64)]) -> Option<u64> {
        mount_map.iter().find_map(|(old, new)| if *old == id { Some(*new) } else { None })
    }
    fn remap_one(p: &mut Option<vfs::VfsPath>, mount_map: &[(u64, u64)]) {
        if let Some(vp) = p.as_mut() {
            if let Some(new_id) = mapped(vp.mnt_id, mount_map) {
                vp.mnt_id = new_id;
            }
        }
    }
    // SAFETY: apply_new_namespaces mutates only `task` while creating its new
    // namespace, before control returns to that task/child.
    unsafe {
        remap_one(&mut *task.cwd_vfs.get(), mount_map);
        remap_one(&mut *task.root_vfs.get(), mount_map);
    }
}
