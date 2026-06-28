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
pub mod tree;

use alloc::fmt::Write;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use alloc::sync::Arc;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::fs::FileSystem;
use vfs::{Dentry, InodeRef, KResult, VfsError};

use tree::Tree;

/// cgroup2 filesystem for the unified mount table (`16§7`). Mounted
/// at `/sys/fs/cgroup`; `vfs::mount::lookup` routes paths here. cgroupfs
/// OWNS its inodes: `lookup` strips the mount prefix, resolves the
/// relative cgroup path through the hierarchy (`tree.rs`), and SYNTHESIZES
/// a `CgDir`/`CgFile` inode — no registry, ZERO devfs dependency.
pub struct CgroupFs;

impl CgroupFs {
    /// Create a cgroup2 filesystem instance. The backing hierarchy is
    /// global; resolution is per-component from the mount root `CgDir`
    /// (`root()` → `CgDir::lookup`), so the instance carries no path prefix.
    /// # C: O(1)
    pub fn new(_mount_point: &str) -> Self { Self }
}

impl FileSystem for CgroupFs {
    /// # C: O(1)
    fn name(&self) -> &str { "cgroup2" }
    /// CGROUP2_SUPER_MAGIC (linux/magic.h) — systemd's `cg_all_unified()`
    /// detects the unified hierarchy by this `statfs` f_type.
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x6367_7270 }
    /// Resolve a `/sys/fs/cgroup/...` path by synthesizing from the
    /// hierarchy: strip the mount prefix → relative cgroup path; the
    /// last component may be a child cgroup (→ `CgDir`) or a control
    /// file of its parent cgroup (→ `CgFile`).
    /// # C: O(components · log n)
    fn root(&self) -> Option<InodeRef> {
        if !is_mounted() { return None; }
        Some(Arc::new(inode::CgDir::new(tree::ROOT)) as InodeRef)
    }
    /// # C: O(1)
    fn mounts_line(&self, mp: &str) -> alloc::string::String {
        let mut s = alloc::string::String::from("cgroup2 ");
        s.push_str(mp);
        s.push_str(" cgroup2 rw,nosuid,nodev,noexec,relatime 0 0\n");
        s
    }
}

/// SIGKILL — raw number (the typed `Signum` lives in `sched`, which
/// this leaf crate cannot depend on without a cycle). Delivered via
/// the registered `SIGNAL_HOOK` for `cgroup.kill`.
const SIGKILL: i32 = 9;

static TREE: Spinlock<Tree, TaskListClass> = Spinlock::new(Tree::new());

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

/// vpid → canonical (global) tid resolver. `cgroup.procs`/`threads`
/// receive a pid as seen in the writer's pid namespace; the cgroup
/// tree keys membership on the canonical tid (matching `/proc/<pid>/
/// cgroup` via `current().tid` and fork-inheritance). The kernel
/// installs this so the leaf crate can translate without a `sched`
/// dependency. Identity fallback when the pid can't be resolved.
static PID_RESOLVE_HOOK: Spinlock<Option<fn(u64) -> u64>, TaskListClass> = Spinlock::new(None);

/// canonical tid → visible pid formatter for cgroup.procs reads. The
/// hierarchy stores canonical tids for kernel accounting, but Linux's
/// cgroupfs ABI exposes PIDs in userspace's PID view. Identity fallback
/// preserves hosted tests and early boot before sched installs the hook.
static PID_DISPLAY_HOOK: Spinlock<Option<fn(u64) -> u64>, TaskListClass> = Spinlock::new(None);

/// `cgroup.events` change-notification: `fn(events_file_path)`. The
/// kernel installs `fs::inotify::fire_modify_path` so a `populated`/
/// `frozen` transition fires inotify `IN_MODIFY` on the node's
/// `cgroup.events` inode (Linux `cgroup_file_notify`). Leaf crate stays
/// `fs`-free. systemd watches this to drive empty-cgroup restart/GC —
/// without it an emptied service cgroup is rmdir'd and never re-realized
/// on restart (`26§4.1`).
static NOTIFY_HOOK: Spinlock<Option<fn(&str)>, TaskListClass> = Spinlock::new(None);

/// Mount-point of the unified hierarchy.
pub const MOUNT: &str = "/sys/fs/cgroup";

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

/// Parse a Linux cpulist (`"0-3,7,9-11"`) into a CPU bitmask (bit N ⇔
/// CPU N), capped at 64. Empty/whitespace → `None` (no restriction).
/// Malformed tokens are skipped (best-effort, matching how the kernel
/// tolerates partial writes). Pure — hosted-tested.
/// # C: O(len)
pub fn cpulist_to_mask(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let mut mask = 0u64;
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() { continue; }
        if let Some((a, b)) = tok.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                for c in lo..=hi.min(63) { if c < 64 { mask |= 1u64 << c; } }
            }
        } else if let Ok(c) = tok.parse::<u32>() {
            if c < 64 { mask |= 1u64 << c; }
        }
    }
    if mask == 0 { None } else { Some(mask) }
}

/// Map cgroup v2 `cpu.weight` (1..=10000, default 100) → CFS load weight
/// (nice-0 == cpu.weight 100 == weight 1024). Saturates to ≥1.
/// # C: O(1)
pub fn cpu_weight_to_cfs(cpu_weight: u32) -> u32 {
    ((cpu_weight as u64 * NICE_0_CFS as u64) / 100).clamp(1, u32::MAX as u64) as u32
}

/// CFS weight of a nice-0 task — kept in sync with `sched::cputime`.
const NICE_0_CFS: u32 = 1024;

/// cpu.max bandwidth-scan decision for one cgroup.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpuAction {
    /// Within quota this period — leave members running.
    Continue,
    /// Over quota this period — freeze members until the next refill.
    Throttle,
    /// Period elapsed — start a new period: unthrottle + re-baseline at
    /// `new_base_ns` (the current cumulative member runtime).
    Refill { new_base_ns: u64 },
}

/// Decide the bandwidth action for a cgroup given the cumulative member
/// runtime `total_ns` (sum of members' sum_exec_runtime), the quota +
/// period, the runtime `base_ns` captured at period start, the period
/// start time, and `now_ns`. Pure — hosted-tested.
///
/// - period elapsed (`now - period_start >= period`) → Refill (re-baseline
///   to `total_ns`, unthrottle).
/// - else consumed (`total - base`) >= quota → Throttle.
/// - else Continue.
/// # C: O(1)
pub fn cpu_bandwidth_decision(
    total_ns: u64, base_ns: u64, quota_ns: u64, period_ns: u64,
    period_start_ns: u64, now_ns: u64,
) -> CpuAction {
    if period_ns == 0 || now_ns.saturating_sub(period_start_ns) >= period_ns {
        return CpuAction::Refill { new_base_ns: total_ns };
    }
    let consumed = total_ns.saturating_sub(base_ns);
    if consumed >= quota_ns { CpuAction::Throttle } else { CpuAction::Continue }
}

/// Install the vpid→tid resolver. Boot path.
/// # C: O(1)
pub fn set_pid_resolve_hook(f: fn(u64) -> u64) { *PID_RESOLVE_HOOK.lock() = Some(f); }

/// Install the tid→visible-pid formatter. Boot path.
/// # C: O(1)
pub fn set_pid_display_hook(f: fn(u64) -> u64) { *PID_DISPLAY_HOOK.lock() = Some(f); }

/// Install the `cgroup.events` inotify hook. Boot path.
/// # C: O(1)
pub fn set_notify_hook(f: fn(&str)) { *NOTIFY_HOOK.lock() = Some(f); }

/// Fire `cgroup.events` `IN_MODIFY` for `cgid` and every ancestor up to
/// root. `populated` is a subtree aggregate, so a membership change in
/// `cgid` can flip an ancestor's `populated` bit — Linux walks
/// `cgroup_file_notify` up the chain. Paths are collected under the tree
/// lock; the hook fires after the lock drops (it re-enters devfs/inotify
/// locks, so must not nest under `TREE`).
/// # C: O(depth) + O(devfs+inotify) per node
fn notify_events_chain(cgid: u64) {
    let hook = match *NOTIFY_HOOK.lock() { Some(h) => h, None => return };
    let paths: Vec<String> = {
        let t = TREE.lock();
        let mut v = Vec::new();
        let mut cur = Some(cgid);
        while let Some(id) = cur {
            let mut p = fs_path(&t, id);
            if !p.ends_with('/') { p.push('/'); }
            p.push_str("cgroup.events");
            v.push(p);
            cur = t.node(id).and_then(|n| n.parent);
        }
        v
    };
    for p in paths { hook(&p); }
}

/// Fire `cgroup.events` `IN_MODIFY` for `cgid` only (the `frozen` field
/// is per-node, not a subtree aggregate, so no ancestor walk).
/// # C: O(devfs+inotify)
fn notify_events_self(cgid: u64) {
    let hook = match *NOTIFY_HOOK.lock() { Some(h) => h, None => return };
    let path = { let t = TREE.lock(); let mut p = fs_path(&t, cgid); if !p.ends_with('/') { p.push('/'); } p.push_str("cgroup.events"); p };
    hook(&path);
}

/// Translate a userspace-written pid (writer's ns) to the canonical
/// tid the tree keys on. Identity when no resolver / no such task.
/// # C: O(resolver)
fn resolve_pid(vpid: u64) -> u64 {
    match *PID_RESOLVE_HOOK.lock() { Some(f) => f(vpid), None => vpid }
}

/// Mount the unified hierarchy at the canonical boot location. Resolves the
/// mountpoint dentry via the namei walk (the root-dentry provider must be
/// installed and `/sys` mounted first, so this runs AFTER the boot `/sys`
/// register). Idempotent from the boot caller's perspective.
/// # C: O(path components)
pub fn mount_root() -> bool {
    let mp = vfs::resolve_path_dentry(MOUNT);
    mount_at(MOUNT, mp).is_ok()
}

/// Mount the shared unified cgroup2 hierarchy on the caller-walked mountpoint
/// dentry `mp` (`mount_point` is its rendered path string, fs INPUT only).
/// Multiple mount instances share the same tree, as Linux does for the
/// unified hierarchy, but each mount shadows its own target dentry.
/// # C: O(N_mounts)
pub fn mount_at(mount_point: &str, mp: Option<Arc<Dentry>>) -> KResult<()> {
    // Guard against a missing/unresolved non-root target turning into an
    // accidental namespace-root mount (`mp == None` ⇒ ns root in the engine).
    if mount_point != "/" && mp.is_none() { return Err(vfs::VfsError::Enoent); }
    let first = TREE.lock().mount_root();
    let fs = Arc::new(CgroupFs::new(mount_point));
    let root = Arc::new(inode::CgDir::new(tree::ROOT)) as InodeRef;
    match vfs::mount::register_bind(mp, fs, root) {
        Ok(()) => Ok(()),
        Err(vfs::VfsError::Eexist) if !first => Ok(()),
        Err(e) => Err(e),
    }
}

/// True iff cgroup `cgid` has a control file named `name`.
/// # C: O(controllers)
pub fn node_has_file(cgid: u64, name: &str) -> bool { TREE.lock().has_file(cgid, name) }

/// Child cgroup id for `name` under `cgid`, if any.
/// # C: O(log n)
pub fn node_child_id(cgid: u64, name: &str) -> Option<u64> { TREE.lock().child_id(cgid, name) }

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
        let display = *PID_DISPLAY_HOOK.lock();
        let mut out = String::new();
        for pid in &n.procs {
            let shown = display.map(|f| f(*pid)).unwrap_or(*pid);
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
    let tid = resolve_pid(vpid);
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
            let tid = resolve_pid(vpid);
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
            if let Some(hook) = *SIGNAL_HOOK.lock() {
                for p in pids { hook(p, SIGKILL); }
            }
            Ok(())
        }
        "cgroup.freeze" => {
            let v = match buf.trim() { "1" => true, "0" => false, _ => return Err(VfsError::Einval) };
            let pids = { let mut t = TREE.lock(); t.set_frozen(cgid, v); t.subtree_pids(cgid) };
            // Actually freeze/thaw each member task via the scheduler.
            if let Some(hook) = *FREEZE_HOOK.lock() {
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
            if let Some(hook) = *WEIGHT_HOOK.lock() {
                for p in pids { hook(p, w); }
            }
            Ok(())
        }
        "cpuset.cpus" => {
            // Persist the cpulist, then push the parsed mask to every
            // member task so the cgroup cpuset restricts their CPUs.
            let pids = { let mut t = TREE.lock(); t.write_file(cgid, file, buf)?; t.subtree_pids(cgid) };
            if let Some(mask) = cpulist_to_mask(buf) {
                if let Some(hook) = *CPUSET_HOOK.lock() {
                    for p in pids { hook(p, mask); }
                }
            }
            Ok(())
        }
        _ => TREE.lock().write_file(cgid, file, buf),
    }
}

/// Full `cgroup.events` fs path of a cgroup node (`MOUNT` + hierarchy
/// path): root → `MOUNT`, else `/sys/fs/cgroup/a/b`. Used only to address
/// the inotify watch target; cgroupfs no longer keys inodes by path.
/// # C: O(depth)
fn fs_path(t: &Tree, cgid: u64) -> String {
    let hp = t.path_of(cgid);
    if hp == "/" { return String::from(MOUNT); }
    let mut s = String::from(MOUNT);
    s.push_str(&hp);
    s
}

/// `mkdir(2)` on a cgroup directory: create the child node in `tree.rs`.
/// Its inodes are synthesized on lookup, so nothing is registered.
/// Returns the new child's cgid.
/// # C: O(log n)
pub fn mkdir_child(parent_cgid: u64, name: &str) -> KResult<u64> {
    let (id, _avail) = TREE.lock().create(parent_cgid, name)?;
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
