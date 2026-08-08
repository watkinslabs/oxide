use sync::{Spinlock, TaskList as TaskListClass};

use crate::{inode::make_cg_file, tree::{MemoryPressure, MemoryPressureResult, Tree}};

/// SIGKILL — raw number (the typed `Signum` lives in `sched`, which
/// this leaf crate cannot depend on without a cycle). Delivered via
/// the registered `SIGNAL_HOOK` for `cgroup.kill`.
pub(crate) const SIGKILL: i32 = 9;

pub(crate) static TREE: Spinlock<Tree, TaskListClass> = Spinlock::new(Tree::new());

/// The hierarchy root's flag word (Linux `cgrp_dfl_root.flags`). cgroup v2 has
/// ONE default root, so these are hierarchy-wide rather than per-mount: a
/// mount or remount naming a flag turns it on for everybody, which is the
/// reference's shape and why a single word is correct here.
static ROOT_FLAGS: Spinlock<crate::root_flags::RootFlags, TaskListClass> =
    Spinlock::new(crate::root_flags::RootFlags::empty());

/// # C: O(1)
pub fn root_flags() -> crate::root_flags::RootFlags { *ROOT_FLAGS.lock() }

/// Install the flags a `mount -t cgroup2 -o ...` supplied. Linux's
/// `cgroup_reconfigure` likewise ORs the newly named flags into the live root
/// rather than replacing the word, so a second mount cannot silently turn a
/// delegation boundary off. # C: O(1)
pub fn add_root_flags(flags: crate::root_flags::RootFlags) {
    let mut g = ROOT_FLAGS.lock();
    let merged = crate::root_flags::RootFlags::from_bits(g.bits() | flags.bits());
    *g = merged;
}

/// The calling task's cgroup-namespace root PATH, installed by the kernel
/// (this leaf crate has no `sched`/`nscg` dependency, the same reason the
/// signal and freeze hooks exist). `None` means the caller is in the initial
/// cgroup namespace, whose root is the hierarchy root.
static NS_ROOT_HOOK: Spinlock<Option<fn() -> Option<alloc::string::String>>, TaskListClass> =
    Spinlock::new(None);

/// # C: O(1)
pub fn set_cgroup_ns_root_hook(h: fn() -> Option<alloc::string::String>) {
    *NS_ROOT_HOOK.lock() = Some(h);
}

/// The caller's cgroup-namespace root path, or `/` when there is no hook or no
/// namespace. # C: O(1) + hook
pub(crate) fn caller_ns_root() -> alloc::string::String {
    let hook = *NS_ROOT_HOOK.lock();
    match hook.and_then(|h| h()) {
        Some(root) if !root.is_empty() => root,
        _ => alloc::string::String::from("/"),
    }
}

/// Signal-delivery hook: `fn(pid, signum)`. Set by the kernel at
/// boot so `cgroup.kill` can SIGKILL every member without this crate
/// depending on `sched`.
static SIGNAL_HOOK: Spinlock<Option<fn(u64, i32)>, TaskListClass> = Spinlock::new(None);

/// `cgroup.freeze` delivery: `(pid, frozen)`. The kernel installs a hook
/// that freezes/thaws the task via the scheduler, so this leaf crate has
/// no `sched` dependency. Mirrors `SIGNAL_HOOK` for `cgroup.kill`.
static FREEZE_HOOK: Spinlock<Option<fn(u64, bool)>, TaskListClass> = Spinlock::new(None);

/// `cpu.weight` delivery: `(pid, cfs_weight)`. The kernel installs a hook
/// that rewrites the task's live CFS load weight so the cgroup weight
/// shifts CPU shares. Leaf crate stays `sched`-free.
static WEIGHT_HOOK: Spinlock<Option<fn(u64, u32)>, TaskListClass> = Spinlock::new(None);

/// `cpuset.cpus` delivery: `(pid, cpu_mask)`. The kernel installs a hook
/// that rewrites the task's `cpus_allowed` so the cgroup cpuset restricts
/// which CPUs its members run on.
static CPUSET_HOOK: Spinlock<Option<fn(u64, u64)>, TaskListClass> = Spinlock::new(None);

/// vpid → canonical (global) tid resolver. `None` means ESRCH for a
/// userspace cgroup.procs write; the tree keys membership on canonical tid.
static PID_RESOLVE_HOOK: Spinlock<Option<fn(u64) -> Option<u64>>, TaskListClass> = Spinlock::new(None);

/// canonical tid → visible pid formatter for cgroup.procs reads.
static PID_DISPLAY_HOOK: Spinlock<Option<fn(u64) -> u64>, TaskListClass> = Spinlock::new(None);

/// canonical tid → visible tid formatter for cgroup.threads reads.
static TID_DISPLAY_HOOK: Spinlock<Option<fn(u64) -> u64>, TaskListClass> = Spinlock::new(None);

/// Scheduler-serialized task migration: `(visible id, destination, thread)`.
static MIGRATE_HOOK: Spinlock<Option<fn(u64, u64, bool) -> vfs::KResult<u64>>, TaskListClass> =
    Spinlock::new(None);

/// `cgroup.events` change-notification: `fn(events_inode)`.
static NOTIFY_HOOK: Spinlock<Option<fn(&vfs::InodeRef)>, TaskListClass> = Spinlock::new(None);

/// PMM/scheduler-owned pressure transaction.  It is invoked after `TREE` is
/// unlocked, so reclaim, throttling, and OOM selection never recurse into the
/// hierarchy lock.  The leaf cgroup crate retains no alternate memory state.
static MEMORY_PRESSURE_HOOK: Spinlock<Option<fn(u64, MemoryPressure) -> MemoryPressureResult>, TaskListClass> = Spinlock::new(None);

/// Install the signal hook. Boot path.
/// # C: O(1)
pub fn set_signal_hook(f: fn(u64, i32)) { *SIGNAL_HOOK.lock() = Some(f); }

/// Install the freezer hook. Boot path.
/// # C: O(1)
pub fn set_freeze_hook(f: fn(u64, bool)) { *FREEZE_HOOK.lock() = Some(f); }

/// Install the cpu.weight hook. Boot path.
/// # C: O(1)
pub fn set_weight_hook(f: fn(u64, u32)) { *WEIGHT_HOOK.lock() = Some(f); }

/// Install the cpuset.cpus hook. Boot path.
/// # C: O(1)
pub fn set_cpuset_hook(f: fn(u64, u64)) { *CPUSET_HOOK.lock() = Some(f); }

/// Install the vpid→tid resolver. Boot path.
/// # C: O(1)
pub fn set_pid_resolve_hook(f: fn(u64) -> Option<u64>) { *PID_RESOLVE_HOOK.lock() = Some(f); }

/// Install the tid→visible-pid formatter. Boot path.
/// # C: O(1)
pub fn set_pid_display_hook(f: fn(u64) -> u64) { *PID_DISPLAY_HOOK.lock() = Some(f); }

/// Install the tid→visible-tid formatter. Boot path. # C: O(1)
pub fn set_tid_display_hook(f: fn(u64) -> u64) { *TID_DISPLAY_HOOK.lock() = Some(f); }

/// Install the scheduler-serialized cgroup migration hook. Boot path. # C: O(1)
pub fn set_migrate_hook(f: fn(u64, u64, bool) -> vfs::KResult<u64>) {
    *MIGRATE_HOOK.lock() = Some(f);
}

/// Install the `cgroup.events` inotify hook. Boot path.
/// # C: O(1)
pub fn set_notify_hook(f: fn(&vfs::InodeRef)) { *NOTIFY_HOOK.lock() = Some(f); }

/// Install the canonical memcg pressure owner. Boot path. # C: O(1)
pub fn set_memory_pressure_hook(f: fn(u64, MemoryPressure) -> MemoryPressureResult) {
    *MEMORY_PRESSURE_HOOK.lock() = Some(f);
}

pub(crate) fn memory_pressure_hook() -> Option<fn(u64, MemoryPressure) -> MemoryPressureResult> {
    *MEMORY_PRESSURE_HOOK.lock()
}

/// Fire `cgroup.events` `IN_MODIFY` for `cgid` and every ancestor up to
/// root. `populated` is a subtree aggregate, so a membership change in
/// `cgid` can flip an ancestor's `populated` bit.
/// # C: O(depth) + O(inotify) per node
pub(crate) fn notify_events_chain(cgid: u64) {
    let hook = match *NOTIFY_HOOK.lock() { Some(h) => h, None => return };
    let ids = {
        let t = TREE.lock();
        let mut v = alloc::vec::Vec::new();
        let mut cur = Some(cgid);
        while let Some(id) = cur {
            v.push(id);
            cur = t.node(id).and_then(|n| n.parent);
        }
        v
    };
    for id in ids {
        let inode = make_cg_file(id, "cgroup.events");
        hook(&inode);
    }
}

/// Fire `cgroup.events` `IN_MODIFY` for `cgid` only (the `frozen` field
/// is per-node, not a subtree aggregate, so no ancestor walk).
/// # C: O(inotify)
pub(crate) fn notify_events_self(cgid: u64) {
    let hook = match *NOTIFY_HOOK.lock() { Some(h) => h, None => return };
    let inode = make_cg_file(cgid, "cgroup.events");
    hook(&inode);
}

/// Translate a userspace-written pid (writer's ns) to the canonical
/// tid the tree keys on. Identity when no resolver / no such task.
/// # C: O(resolver)
pub(crate) fn resolve_pid(vpid: u64) -> Option<u64> {
    match *PID_RESOLVE_HOOK.lock() { Some(f) => f(vpid), None => Some(vpid) }
}

pub(crate) fn visible_pid(pid: u64) -> u64 {
    match *PID_DISPLAY_HOOK.lock() {
        Some(f) => f(pid),
        None => pid,
    }
}

/// Translate a canonical thread id to its visible namespace id.
/// # C: O(1)
pub(crate) fn visible_tid(tid: u64) -> u64 {
    match *TID_DISPLAY_HOOK.lock() {
        Some(f) => f(tid),
        None => tid,
    }
}

/// Migrate one thread or its entire thread group through the scheduler owner.
/// # C: O(number of threads) for process migration, O(1) for thread migration
pub(crate) fn migrate_task(vpid: u64, cgid: u64, thread: bool) -> vfs::KResult<u64> {
    let hook = *MIGRATE_HOOK.lock();
    match hook {
        Some(f) => f(vpid, cgid, thread),
        None => {
            let tid = resolve_pid(vpid).ok_or(vfs::VfsError::Esrch)?;
            if thread { crate::migrate_thread(cgid, tid) } else { crate::migrate_process(cgid, tid) }
        }
    }
}

pub(crate) fn signal_hook() -> Option<fn(u64, i32)> {
    *SIGNAL_HOOK.lock()
}

pub(crate) fn freeze_hook() -> Option<fn(u64, bool)> {
    *FREEZE_HOOK.lock()
}

pub(crate) fn weight_hook() -> Option<fn(u64, u32)> {
    *WEIGHT_HOOK.lock()
}

pub(crate) fn cpuset_hook() -> Option<fn(u64, u64)> {
    *CPUSET_HOOK.lock()
}

/// Hugetlb charge-reparent hook: `fn(from_cgid, to_cgid)`. A cgroup being
/// removed hands its outstanding huge-page charges to its parent, and the
/// owner recorded against each charged page has to follow — otherwise the
/// eventual release names a cgroup that is gone and the charge is stranded on
/// the parent forever. The huge-page pool holds those owner records, so it
/// installs the hook rather than this leaf crate reaching into it.
static HUGETLB_REPARENT_HOOK: Spinlock<Option<fn(u64, u64)>, TaskListClass> = Spinlock::new(None);

/// # C: O(1)
pub fn set_hugetlb_reparent_hook(h: fn(u64, u64)) { *HUGETLB_REPARENT_HOOK.lock() = Some(h); }

/// # C: O(1)
pub(crate) fn hugetlb_reparent_hook() -> Option<fn(u64, u64)> { *HUGETLB_REPARENT_HOOK.lock() }
