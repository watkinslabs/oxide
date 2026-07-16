// cgroup v2 unified hierarchy per `26§4`. Single tree mounted at
// `/sys/fs/cgroup`; controllers cpu/memory/io/pids/cpuset. This crate
// owns the hierarchy state (`tree`) + the VFS bridge (`inode`); the
// kernel wires the sched↔cgroup glue (fork inheritance, signal
// delivery for cgroup.kill, `/proc/<pid>/cgroup`) via the hooks here,
// keeping this a leaf crate (no sched dependency → no cycle).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(feature = "debug-cgroup")]
pub mod selftest;

pub mod inode;
pub mod fs;
pub mod policy;
pub mod state;
pub mod tree;
mod ids;

use alloc::fmt::Write;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vfs::{KResult, VfsError};

pub use fs::{mount_at, realize_tree, CgroupFs};
pub use policy::{CpuAction, cpu_bandwidth_decision, cpulist_to_mask, cpu_weight_to_cfs};
pub use state::{
    set_cpuset_hook, set_freeze_hook, set_notify_hook, set_pid_display_hook, set_pid_resolve_hook,
    set_signal_hook, set_weight_hook,
};
use state::{
    SIGKILL, TREE, cpuset_hook, freeze_hook, notify_events_chain, notify_events_self, resolve_pid,
    signal_hook, visible_pid, weight_hook,
};

/// Mount-point of the unified hierarchy.
pub const MOUNT: &str = "/sys/fs/cgroup";

/// True iff cgroup `cgid` has a control file named `name`.
/// # C: O(controllers)
pub fn node_has_file(cgid: u64, name: &str) -> bool { TREE.lock().has_file(cgid, name) }

/// Child cgroup id for `name` under `cgid`, if any.
/// # C: O(log n)
pub fn node_child_id(cgid: u64, name: &str) -> Option<u64> { TREE.lock().child_id(cgid, name) }

/// DAC owner `(uid, gid)` of cgroup `cgid`'s DIRECTORY inode. The inode is
/// synthesized fresh on every lookup, so its owner is read back from the
/// hierarchy here. # C: O(log n)
pub fn node_dir_owner(cgid: u64) -> (u32, u32) { TREE.lock().dir_owner(cgid) }

/// DAC owner `(uid, gid)` of the control file `(cgid, file)`. # C: O(log n)
pub fn node_file_owner(cgid: u64, file: &str) -> (u32, u32) { TREE.lock().file_owner(cgid, file) }

/// `chown(2)` write-through for a cgroup DIRECTORY inode — persists the owner
/// in the hierarchy so systemd's delegation survives inode re-synthesis.
/// # C: O(log n)
pub fn chown_dir(cgid: u64, uid: u32, gid: u32) -> KResult<()> {
    TREE.lock().set_dir_owner(cgid, uid, gid)
}

/// `chown(2)` write-through for a cgroup CONTROL-FILE inode. # C: O(log n)
pub fn chown_file(cgid: u64, file: &str, uid: u32, gid: u32) -> KResult<()> {
    TREE.lock().set_file_owner(cgid, file, uid, gid)
}

/// Ordered control-file names of cgroup `cgid` (for readdir).
/// # C: O(controllers)
pub fn node_file_names(cgid: u64) -> Vec<&'static str> { TREE.lock().node_files(cgid) }

/// Ordered child-cgroup names of `cgid` (for readdir).
/// # C: O(children)
pub fn node_child_names(cgid: u64) -> Vec<String> { TREE.lock().child_names(cgid) }

/// True once `/sys/fs/cgroup` is mounted.
/// # C: O(1)
pub fn is_mounted() -> bool { TREE.lock().is_mounted() }

/// Read a control file `(cgid, file)`.
/// # C: O(subtree) for populated/pids; O(members) for procs
pub fn read_file(cgid: u64, file: &str) -> KResult<Vec<u8>> {
    if file == "cgroup.procs" || file == "cgroup.threads" {
        let t = TREE.lock();
        let n = t.node(cgid).ok_or(VfsError::Enoent)?;
        let mut out = String::new();
        for pid in &n.procs {
            let shown = visible_pid(*pid);
            let _ = writeln!(out, "{shown}");
        }
        return Ok(out.into_bytes());
    }
    TREE.lock().read_file(cgid, file)
}

/// CLONE_INTO_CGROUP (clone3): place the just-cloned child `vpid` into `cgid`.
/// Mirrors a `cgroup.procs` write but takes the vpid directly — used by the
/// clone3 ABI shim when the caller passes a cgroup fd. systemd's pidfd_spawn
/// relies on this to land service executors in the right cgroup v2 node.
/// # C: O(members)
pub fn attach_into(cgid: u64, vpid: u64) {
    if let Some(tid) = resolve_pid(vpid) { attach_tid_into(cgid, tid); }
}

/// Place canonical task `tid` into `cgid` before it can run. Used by
/// clone3(CLONE_INTO_CGROUP), whose child is born in the destination cgroup.
/// # C: O(members)
pub fn attach_tid_into(cgid: u64, tid: u64) {
    let src = TREE.lock().cgroup_of(tid);
    TREE.lock().add_proc(cgid, tid);
    if src != cgid { notify_events_chain(src); }
    notify_events_chain(cgid);
}

/// Recover the cgroup id from a cgroup2 DIRECTORY inode's `(ino, fsid)`.
/// `None` when the inode is not a cgroup2 directory. Lets the clone3 shim
/// resolve the caller's `CLONE_INTO_CGROUP` cgroup fd to a `cgid` without the
/// shim depending on cgroup-internal inode constants. # C: O(1)
pub fn cgid_from_dir_inode(ino: u64, fsid: u64) -> Option<u64> {
    // Mirrors inode.rs: CgDir::ino() = DIR_INO_BASE + cgid; fsid = CGROUP2_FSID.
    const CGROUP2_FSID: u64 = 0x6367_7270;
    const DIR_INO_BASE: u64 = 0x6000_0000;
    if fsid == CGROUP2_FSID && ino >= DIR_INO_BASE && ino < DIR_INO_BASE + 0x0100_0000 {
        Some(ino - DIR_INO_BASE)
    } else {
        None
    }
}

/// Write a control file. Handles the cross-subsystem files
/// (cgroup.procs/threads/subtree_control/kill/freeze) here; delegates
/// per-controller limit files to the tree.
/// # C: O(tokens) + O(members) for kill
pub fn write_file(cgid: u64, file: &str, buf: &str) -> KResult<()> {
    match file {
        "cgroup.procs" | "cgroup.threads" => {
            #[cfg(feature = "debug-cgroup")]
            {
                klog::write_raw(b"[cg] write ");
                klog::write_raw(file.as_bytes());
                klog::write_raw(b" cgid=");
                klog::write_dec_u64(cgid);
                klog::write_raw(b" buf=");
                klog::write_raw(buf.as_bytes());
                klog::write_raw(b"\n");
            }
            let vpid: u64 = buf.trim().parse().map_err(|_| VfsError::Einval)?;
            // Membership keys on the canonical tid (what `current().tid`
            // and fork-inheritance use); the written value is a vpid in
            // the writer's pid namespace. Translate before storing.
            let tid = resolve_pid(vpid).ok_or(VfsError::Esrch)?;
            // Source cgroup (before the move) may flip populated 1→0;
            // destination may flip 0→1 — notify both chains.
            let src = TREE.lock().cgroup_of(tid);
            TREE.lock().add_proc(cgid, tid);
            if src != cgid { notify_events_chain(src); }
            notify_events_chain(cgid);
            Ok(())
        }
        "cgroup.subtree_control" => {
            // Children's available-controller set (and thus their visible
            // interface files) is recomputed live on every readdir/lookup
            // from `tree.rs`, so enabling/disabling a controller needs no
            // registry sync — just apply the write to the hierarchy.
            TREE.lock().write_subtree_control(cgid, buf)?;
            Ok(())
        }
        "cgroup.kill" => {
            if buf.trim() != "1" { return Err(VfsError::Einval); }
            let pids = TREE.lock().subtree_pids(cgid);
            if let Some(hook) = signal_hook() {
                for p in pids { hook(p, SIGKILL); }
            }
            Ok(())
        }
        "cgroup.freeze" => {
            let v = match buf.trim() { "1" => true, "0" => false, _ => return Err(VfsError::Einval) };
            let pids = { let mut t = TREE.lock(); t.set_frozen(cgid, v); t.subtree_pids(cgid) };
            // Actually freeze/thaw each member task via the scheduler.
            if let Some(hook) = freeze_hook() {
                for p in pids { hook(p, v); }
            }
            // `frozen` field changed → cgroup.events IN_MODIFY.
            notify_events_self(cgid);
            Ok(())
        }
        "cpu.weight" => {
            // Persist the value, then push the mapped CFS weight to every
            // member task so the cgroup weight actually shifts CPU shares.
            let pids = { let mut t = TREE.lock(); t.write_file(cgid, file, buf)?; t.subtree_pids(cgid) };
            let w = cpu_weight_to_cfs(TREE.lock().node(cgid).map(|n| n.cpu_weight).unwrap_or(100));
            if let Some(hook) = weight_hook() {
                for p in pids { hook(p, w); }
            }
            Ok(())
        }
        "cpuset.cpus" => {
            // Persist the cpulist, then push the parsed mask to every
            // member task so the cgroup cpuset restricts their CPUs.
            let pids = { let mut t = TREE.lock(); t.write_file(cgid, file, buf)?; t.subtree_pids(cgid) };
            if let Some(mask) = cpulist_to_mask(buf) {
                if let Some(hook) = cpuset_hook() {
                    for p in pids { hook(p, mask); }
                }
            }
            Ok(())
        }
        _ => TREE.lock().write_file(cgid, file, buf),
    }
}

/// `mkdir(2)` on a cgroup directory: create the child node in `tree.rs`.
/// Its inodes are synthesized on lookup, so nothing is registered. `uid`/`gid`
/// are the creating task's fsuid/fsgid (Linux `cgroup_create` stamps
/// `current_fsuid`/`current_fsgid` on the new dir + its interface files), so a
/// delegated user's own sub-cgroups are user-owned and writable. Returns the
/// new child's cgid. # C: O(log n)
pub fn mkdir_child(parent_cgid: u64, name: &str, uid: u32, gid: u32) -> KResult<u64> {
    let mut t = TREE.lock();
    let (id, _avail) = t.create(parent_cgid, name)?;
    t.set_created_owner(id, uid, gid);
    Ok(id)
}

/// `rmdir(2)` on a cgroup directory: remove the (empty) child node from
/// `tree.rs`. No registry to clean up — inodes were synthesized.
/// # C: O(log n)
pub fn rmdir_child(parent_cgid: u64, name: &str) -> KResult<()> {
    let id = {
        let t = TREE.lock();
        *t.node(parent_cgid).ok_or(VfsError::Enoent)?
            .children.get(name).ok_or(VfsError::Enoent)?
    };
    TREE.lock().remove(id)
}

// --- sched glue ----------------------------------------------------

/// True iff forking one more task in `cgid`'s subtree would exceed an
/// ancestor `pids.max` (the kernel returns EAGAIN). Defaults to the
/// task's current cgroup; root is unlimited.
/// # C: O(depth · subtree)
pub fn fork_would_exceed_pids(pid: u64) -> bool {
    let t = TREE.lock();
    if !t.is_mounted() { return false; }
    let cg = t.cgroup_of(pid);
    t.fork_would_exceed_pids(cg)
}

/// True iff one more task born directly into `cgid` would exceed pids.max.
/// # C: O(depth · subtree)
pub fn fork_would_exceed_cgroup(cgid: u64) -> bool {
    let t = TREE.lock();
    if !t.is_mounted() { return false; }
    t.fork_would_exceed_pids(cgid)
}

/// Try to charge `bytes` to `pid`'s cgroup memory controller. Returns
/// true (charged) when unmounted or under every ancestor `memory.max`;
/// false means the caller must fail the allocation with ENOMEM.
/// # C: O(depth · subtree)
pub fn try_charge(pid: u64, bytes: u64) -> bool {
    let mut t = TREE.lock();
    if !t.is_mounted() { return true; }
    t.try_charge_mem(pid, bytes)
}

/// Uncharge `bytes` of freed memory from `pid`'s cgroup.
/// # C: O(log n)
pub fn uncharge(pid: u64, bytes: u64) {
    let mut t = TREE.lock();
    if t.is_mounted() { t.uncharge_mem(pid, bytes); }
}

/// Charge a completed block I/O of `bytes` to `pid`'s cgroup io.stat.
/// No-op when unmounted. `is_write` selects r/w counters.
///
/// Uses `try_lock`, NOT `lock`: this runs on the hot page-cache io path,
/// and `TREE`'s spinlock does not disable preemption — spinning here while
/// a preempted task holds the lock would deadlock (esp. under SMP
/// preemption). On contention we simply drop the sample; io.stat is
/// approximate accounting (Linux's is too), never a correctness gate.
/// # C: O(log n)
pub fn charge_io(pid: u64, bytes: u64, is_write: bool) {
    if let Some(mut t) = TREE.try_lock() {
        if t.is_mounted() { t.charge_io(pid, bytes, is_write); }
    }
}

/// Snapshot cgroups with a cpu.max quota for the bandwidth scanner.
/// Empty when unmounted. See `tree::Tree::cpu_quota_groups`.
/// # C: O(N nodes + members)
pub fn cpu_quota_groups() -> alloc::vec::Vec<tree::CpuGroup> {
    let t = TREE.lock();
    if !t.is_mounted() { return alloc::vec::Vec::new(); }
    t.cpu_quota_groups()
}

/// Commit a bandwidth-scan decision (throttled flag + period re-baseline).
/// # C: O(log n)
pub fn set_cpu_state(cgid: u64, throttled: bool, base_ns: u64, period_start_ns: u64) {
    let mut t = TREE.lock();
    if t.is_mounted() { t.set_cpu_state(cgid, throttled, base_ns, period_start_ns); }
}

/// Child inherits the parent's cgroup on fork.
/// # C: O(log n)
pub fn inherit(child_pid: u64, parent_pid: u64) {
    let mut t = TREE.lock();
    if !t.is_mounted() { return; }
    let cg = t.cgroup_of(parent_pid);
    t.add_proc(cg, child_pid);
}

/// Drop a process from its cgroup on exit.
/// # C: O(log n)
pub fn on_exit(pid: u64) {
    let cg = {
        let mut t = TREE.lock();
        if !t.is_mounted() { return; }
        // Capture the membership cgroup BEFORE removal so the notify
        // walk targets the chain whose `populated` may now flip to 0.
        let cg = t.cgroup_of(pid);
        t.remove_proc(pid);
        t.remove_thread(pid);
        cg
    };
    // Last task leaving a cgroup flips `populated` 1→0; systemd's
    // empty-cgroup handler is driven by this inotify event (`26§4.1`).
    notify_events_chain(cg);
}

/// Charge a new thread (`CLONE_THREAD`) to its process's cgroup so
/// pids.current counts it (Linux pids controller counts every task).
/// # C: O(log n)
pub fn charge_thread(parent_pid: u64, tid: u64) {
    let mut t = TREE.lock();
    if t.is_mounted() { t.add_thread(parent_pid, tid); }
}

/// `/proc/<pid>/cgroup` line — `0::<path>\n` for the unified
/// hierarchy (Linux format; controller field empty for v2).
/// # C: O(depth)
pub fn proc_cgroup(pid: u64) -> String {
    let t = TREE.lock();
    if !t.is_mounted() { return "0::/\n".to_string(); }
    let cg = t.cgroup_of(pid);
    let mut s = String::from("0::");
    s.push_str(&t.path_of(cg));
    s.push('\n');
    s
}

#[cfg(test)]
mod tests;
