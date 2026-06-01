// cgroup v2 unified hierarchy per `26§4`. Single tree mounted at
// `/sys/fs/cgroup`; controllers cpu/memory/io/pids/cpuset. This crate
// owns the hierarchy state (`tree`) + the VFS bridge (`inode`); the
// kernel wires the sched↔cgroup glue (fork inheritance, signal
// delivery for cgroup.kill, `/proc/<pid>/cgroup`) via the hooks here,
// keeping this a leaf crate (no sched dependency → no cycle).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod inode;
pub mod tree;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use alloc::sync::Arc;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::fs::FileSystem;
use vfs::{InodeRef, KResult, VfsError};

use tree::Tree;

/// cgroup2 filesystem for the unified mount table (`16§7`). Mounted
/// at `/sys/fs/cgroup`; `vfs::mount::lookup` routes paths here. v1
/// backends key by full absolute path, so `lookup` delegates to the
/// devfs registry where `mount_root`/`mkdir_child` register the
/// CgDir/CgFile inodes.
pub struct CgroupFs;

impl FileSystem for CgroupFs {
    /// # C: O(1)
    fn name(&self) -> &str { "cgroup2" }
    /// CGROUP2_SUPER_MAGIC (linux/magic.h) — systemd's `cg_all_unified()`
    /// detects the unified hierarchy by this `statfs` f_type.
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x6367_7270 }
    /// # C: O(N devfs registry)
    fn lookup(&self, path: &str) -> Option<InodeRef> { devfs::lookup(path) }
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

/// Translate a userspace-written pid (writer's ns) to the canonical
/// tid the tree keys on. Identity when no resolver / no such task.
/// # C: O(resolver)
fn resolve_pid(vpid: u64) -> u64 {
    match *PID_RESOLVE_HOOK.lock() { Some(f) => f(vpid), None => vpid }
}

/// Mount the unified hierarchy: create the root node and register its
/// directory + core control files in devfs. Idempotent (re-mount is a
/// no-op success). Returns true on the first mount.
/// # C: O(1)
pub fn mount_root() -> bool {
    let first = TREE.lock().mount_root();
    if first {
        let rows = inode::build_inodes(tree::ROOT, MOUNT, tree::ALL, true);
        for (p, ino) in rows { devfs::register_owned(p, ino); }
        // Route /sys/fs/cgroup/* through CgroupFs in the unified mount
        // table so open()/read/write reach these inodes (`16§7`).
        let _ = vfs::mount::register(MOUNT, Arc::new(CgroupFs));
    }
    first
}

/// True once `/sys/fs/cgroup` is mounted.
/// # C: O(1)
pub fn is_mounted() -> bool { TREE.lock().is_mounted() }

/// Read a control file `(cgid, file)`.
/// # C: O(subtree) for populated/pids; O(members) for procs
pub fn read_file(cgid: u64, file: &str) -> KResult<Vec<u8>> {
    TREE.lock().read_file(cgid, file)
}

/// Write a control file. Handles the cross-subsystem files
/// (cgroup.procs/threads/subtree_control/kill/freeze) here; delegates
/// per-controller limit files to the tree.
/// # C: O(tokens) + O(members) for kill
pub fn write_file(cgid: u64, file: &str, buf: &str) -> KResult<()> {
    match file {
        "cgroup.procs" | "cgroup.threads" => {
            let vpid: u64 = buf.trim().parse().map_err(|_| VfsError::Einval)?;
            // Membership keys on the canonical tid (what `current().tid`
            // and fork-inheritance use); the written value is a vpid in
            // the writer's pid namespace. Translate before storing.
            let tid = resolve_pid(vpid);
            TREE.lock().add_proc(cgid, tid);
            Ok(())
        }
        "cgroup.subtree_control" => {
            let (old, new) = {
                let mut t = TREE.lock();
                let old = t.node(cgid).map(|n| n.subtree_control).unwrap_or(0);
                let new = t.write_subtree_control(cgid, buf)?;
                (old, new)
            };
            if old != new { sync_children_controller_files(cgid, old, new); }
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

/// `mkdir(2)` on a cgroup directory: create the child node and
/// register its dir + control files. Returns the new dir inode.
/// Full devfs path of a cgroup node: `MOUNT` + the hierarchy path
/// (`tree::path_of` yields `/a/b`, the devfs registry keys on the
/// mount-prefixed `/sys/fs/cgroup/a/b`). Root maps to `MOUNT`.
/// # C: O(depth)
fn fs_path(t: &Tree, cgid: u64) -> String {
    let hp = t.path_of(cgid);
    if hp == "/" { return String::from(MOUNT); }
    let mut s = String::from(MOUNT);
    s.push_str(&hp);
    s
}

/// # C: O(files)
pub fn mkdir_child(parent_cgid: u64, parent_path: &str, name: &str) -> KResult<InodeRef> {
    let (id, avail) = TREE.lock().create(parent_cgid, name)?;
    let mut path = String::from(parent_path);
    if !path.ends_with('/') { path.push('/'); }
    path.push_str(name);
    let rows = inode::build_inodes(id, &path, avail, false);
    let dir = rows.first().map(|(_, i)| i.clone());
    for (p, ino) in rows { devfs::register_owned(p, ino); }
    dir.ok_or(VfsError::Eio)
}

/// `rmdir(2)` on a cgroup directory: remove the (empty) child node and
/// unregister its dir + files from devfs.
/// # C: O(registry)
pub fn rmdir_child(parent_cgid: u64, name: &str) -> KResult<()> {
    let (id, path) = {
        let t = TREE.lock();
        let cid = *t.node(parent_cgid).ok_or(VfsError::Enoent)?
            .children.get(name).ok_or(VfsError::Enoent)?;
        (cid, fs_path(&t, cid))
    };
    TREE.lock().remove(id)?;
    devfs::unregister_subtree(0, &path);
    Ok(())
}

/// Add/remove controller interface files on a node's existing children
/// when the parent's subtree_control changes availability.
fn sync_children_controller_files(parent: u64, old: u8, new: u8) {
    let kids: Vec<(u64, String)> = {
        let t = TREE.lock();
        match t.node(parent) {
            Some(n) => n.children.values().map(|&c| (c, fs_path(&t, c))).collect(),
            None => return,
        }
    };
    let added = new & !old;
    let removed = old & !new;
    for (cid, cpath) in kids {
        if removed != 0 {
            for f in tree::controller_files(removed) {
                let mut fp = cpath.clone(); fp.push('/'); fp.push_str(f);
                devfs::unregister_subtree(0, &fp);
            }
        }
        if added != 0 {
            let mut seq = (cid << 8) + 0x80;
            for f in tree::controller_files(added) {
                let mut fp = cpath.clone(); fp.push('/'); fp.push_str(f);
                devfs::register_owned(fp, alloc::sync::Arc::new(
                    inode::CgFile::new(cid, f, seq)) as InodeRef);
                seq += 1;
            }
        }
    }
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
    let mut t = TREE.lock();
    if t.is_mounted() { t.remove_proc(pid); t.remove_thread(pid); }
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
