// 272 unshare — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

const CLONE_NEWNS:    u64 = 0x00020000;
const CLONE_NEWCGROUP:u64 = 0x02000000;
const CLONE_NEWUTS:   u64 = 0x04000000;
const CLONE_NEWIPC:   u64 = 0x08000000;
const CLONE_NEWUSER:  u64 = 0x10000000;
const CLONE_NEWPID:   u64 = 0x20000000;
const CLONE_NEWNET:   u64 = 0x40000000;

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

/// `sys_unshare(flags)` — slot 272. Detach the calling task from
/// the named namespaces. v1 honors CLONE_NEWUTS by snapshotting the
/// current global hostname into a per-task UTS slot. Other CLONE_NEW*
/// bits set the membership bit but per-NS isolation isn't enforced.
/// # C: O(1)
pub fn sys_unshare(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let flags = args.a0;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let mut bits: u64 = 0;
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
    if bits == 0 { return 0; }
    cur.ns_membership.fetch_or(bits, Ordering::Release);
    if (bits & (1u64 << 1)) != 0 {
        let snap_bytes = crate::hostname::snapshot();
        let snap = alloc::string::String::from_utf8(snap_bytes).unwrap_or_default();
        // SAFETY: per-task slot single-mutator per `13§5`; running task on this CPU is the sole writer of uts_hostname.
        unsafe { *cur.uts_hostname.get() = snap; }
    }
    if (bits & (1u64 << 2)) != 0 {
        // CLONE_NEWIPC — fresh ipc_ns id (F100).
        static NEXT_IPC_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_IPC_NS.fetch_add(1, Ordering::AcqRel);
        cur.ipc_ns.store(id, Ordering::Release);
    }
    if (bits & (1u64 << 5)) != 0 {
        // CLONE_NEWNET — fresh net_ns id (F101).
        static NEXT_NET_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_NET_NS.fetch_add(1, Ordering::AcqRel);
        cur.net_ns.store(id, Ordering::Release);
    }
    if (bits & (1u64 << 4)) != 0 {
        // CLONE_NEWPID — pending bit; fork dispatcher allocates ns (F105).
        cur.unshare_pid_pending.store(true, Ordering::Release);
    }
    if (bits & (1u64 << 3)) != 0 {
        // CLONE_NEWUSER — fresh user_ns id (F106 substrate).
        // F118: also record (new, parent) so has_cap_for can walk
        // ancestors per `27§R01`.
        static NEXT_USER_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let new_id = NEXT_USER_NS.fetch_add(1, Ordering::AcqRel);
        let parent = cur.user_ns.load(Ordering::Acquire);
        nscg::proc_ns::user_ns_record(new_id, parent);
        cur.parent_user_ns.store(parent, Ordering::Release);
        cur.user_ns.store(new_id, Ordering::Release);
    }
    if (bits & (1u64 << 6)) != 0 {
        // CLONE_NEWCGROUP — fresh cgroup_ns id (F106 substrate).
        static NEXT_CGROUP_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let id = NEXT_CGROUP_NS.fetch_add(1, Ordering::AcqRel);
        cur.cgroup_ns.store(id, Ordering::Release);
    }
    if (bits & (1u64 << 0)) != 0 {
        // CLONE_NEWNS — fresh mount_ns id (F107 substrate) + snapshot
        // parent's NS-tagged mount entries into the new id (F119).
        static NEXT_MOUNT_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        let new_id = NEXT_MOUNT_NS.fetch_add(1, Ordering::AcqRel);
        let parent_ns = cur.mount_ns.load(Ordering::Acquire);
        devfs::snapshot_ns(parent_ns, new_id);
        // U2-b: copy the unified mount table's entries too, so the new ns
        // starts with a full private copy of the parent tree then diverges.
        vfs::mount::snapshot_ns(parent_ns, new_id);
        cur.mount_ns.store(new_id, Ordering::Release);
    }
    0
}
