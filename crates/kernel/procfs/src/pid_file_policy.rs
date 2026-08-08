// Per-pid `/proc` file POLICY, matching Linux's tgid_base_stuff
// mode column, `task_dump_owner` / `pid_update_inode`, and which entries gate
// their CONTENT behind `ptrace_may_access` (`lock_trace` for the `ONE(...)`
// entries, `proc_mem_open`/`mm_access` for `environ`/`auxv`/`maps`/`smaps`).
//
// No target gate: every one of these is a security decision, so it must be
// hosted-testable. `live/pid_dir.rs` looks up a name here and stamps the
// resulting inode; it decides nothing itself.

#[cfg(test)] mod tests;

/// `S_IRUGO` — world-readable, the `/proc` default.
pub const MODE_RUGO: u16 = 0o444;
/// `S_IRUSR` — owner-only. Linux uses it for every per-pid file whose content
/// leaks the task's address space or execution state.
pub const MODE_RUSR: u16 = 0o400;
/// `S_IRUGO|S_IWUSR` — readable by all, writable by the owner.
pub const MODE_RUGO_WUSR: u16 = 0o644;
/// `S_IRUGO|S_IWUGO` — `timerslack_ns` alone.
pub const MODE_RUGO_WUGO: u16 = 0o666;
/// `S_IRUGO|S_IXUGO` — the world-searchable per-pid directories.
pub const MODE_DIR_RUGO: u16 = 0o555;
/// `S_IRUSR|S_IXUSR` — `fd/` and `map_files/`, owner-only.
pub const MODE_DIR_RUSR: u16 = 0o500;
/// `S_IRUSR|S_IXUGO` — `ns/`: only the owner may list it, but anyone may
/// traverse into a named entry.
pub const MODE_DIR_NS: u16 = 0o511;

/// Linux `prctl` `SUID_DUMP_USER` — the only dumpable value for which a task's
/// `/proc` files keep the task's own ownership.
pub const SUID_DUMP_USER: u8 = 1;

/// The mode Linux's `tgid_base_stuff` / `tid_base_stuff` table gives `name`.
/// Unknown names fall to the world-readable default, which is what the
/// remaining `ONE(..., S_IRUGO, ...)` entries carry. # C: O(N_entries)
pub fn pid_file_mode(name: &str) -> u16 {
    match name {
        // S_IRUSR: content exposes the address space or execution state.
        "environ" | "auxv" | "personality" | "syscall" | "stack" | "mountstats"
        | "io" | "pagemap" | "ksm_stat" | "ksm_merging_pages" | "patch_state"
        | "seccomp_cache" => MODE_RUSR,
        // S_IRUGO|S_IWUSR.
        "sched" | "autogroup" | "timens_offsets" | "comm" | "oom_adj"
        | "oom_score_adj" | "loginuid" | "coredump_filter" | "make-it-fail"
        | "uid_map" | "gid_map" | "projid_map" | "setgroups" => MODE_RUGO_WUSR,
        "timerslack_ns" => MODE_RUGO_WUGO,
        // S_IWUSR only.
        "clear_refs" => 0o200,
        // Directories.
        "fd" | "map_files" => MODE_DIR_RUSR,
        "ns" => MODE_DIR_NS,
        "task" | "fdinfo" | "net" | "attr" => MODE_DIR_RUGO,
        _ => MODE_RUGO,
    }
}

/// Does reading this entry's CONTENT require `ptrace_may_access` on the target
/// (Linux `lock_trace` for the `ONE()` entries, `proc_mem_open`/`mm_access` for
/// the mm-backed ones)? DAC alone is not enough for these: a same-uid task that
/// dropped privileges and became non-dumpable must still be refused, and a
/// CAP_SYS_PTRACE holder must still be allowed. # C: O(N_entries)
pub fn needs_ptrace_gate(name: &str) -> bool {
    matches!(name,
        // lock_trace(): ptrace_may_access(PTRACE_MODE_ATTACH_FSCREDS).
        "personality" | "syscall" | "stack" | "seccomp_cache"
        // proc_mem_open()/mm_access(): PTRACE_MODE_READ_FSCREDS on the mm.
        | "environ" | "auxv" | "mem" | "maps" | "smaps" | "smaps_rollup"
        | "numa_maps" | "pagemap" | "clear_refs"
        // task_io_accounting: ptrace_may_access(PTRACE_MODE_READ_FSCREDS).
        | "io" | "ksm_stat" | "ksm_merging_pages")
}

/// Linux `task_dump_owner`. A per-pid `/proc` node is owned by the task's
/// EFFECTIVE ids — except that a kernel thread's nodes, and (for everything but
/// the world-searchable per-pid DIRECTORY itself) a non-dumpable task's nodes,
/// are owned by root. That exception is what stops a setuid binary's `/proc`
/// files from becoming readable by the unprivileged uid that spawned it.
///
/// `world_searchable_dir` is Linux's literal `mode != (S_IFDIR | S_IRUGO |
/// S_IXUGO)` test — every per-process world-readable AND world-executable
/// DIRECTORY is exempt, not just `/proc/<pid>` itself, so `stat /proc/<pid>`
/// keeps reporting the task's euid even when the task is not dumpable (procps
/// relied on that long before `status` existed). Use [`is_world_searchable_dir`]
/// to compute it from a mode rather than re-deriving the test.
/// # C: O(1)
pub fn dump_owner(kthread: bool, euid: u32, egid: u32, dumpable: u8,
                  world_searchable_dir: bool) -> (u32, u32) {
    if kthread { return (0, 0); }
    if !world_searchable_dir && dumpable != SUID_DUMP_USER { return (0, 0); }
    (euid, egid)
}

/// Linux's `mode == (S_IFDIR | S_IRUGO | S_IXUGO)` predicate over the entry's
/// table mode plus whether the entry is a directory. # C: O(1)
pub fn is_world_searchable_dir(is_dir: bool, mode: u16) -> bool {
    is_dir && mode == MODE_DIR_RUGO
}

/// The live facts a cached per-pid node's revalidation needs about its task.
pub struct TaskOwner { pub kthread: bool, pub euid: u32, pub egid: u32, pub dumpable: u8 }

/// `S_ISUID | S_ISGID` — cleared from every per-pid node.
const SUID_SGID: u16 = 0o6000;

/// Linux `pid_revalidate` + `pid_update_inode` for one CACHED per-pid node.
///
/// A per-pid node's ownership is a snapshot of credentials that change under it:
/// the task may `setuid()` (systemd's per-user manager drops to the session uid
/// between the fork that populates the dcache and the exec that uses it), or die
/// and have its pid recycled. Serving the cached inode without this re-stamp
/// hands the new credentials the OLD owner — `/proc/self/fd` stays root-owned
/// after the drop, and `opendir` on the task's own fd directory fails `EACCES`.
///
/// `None` ⇒ the task is gone; the caller drops the dentry so the next lookup
/// rebuilds it (Linux returns 0 from `d_revalidate`). `Some((uid, gid, mode))`
/// ⇒ re-stamp; only ownership and the suid bits move, never the table mode.
/// # C: O(1)
pub fn revalidate_pid_inode(task: Option<TaskOwner>, is_dir: bool, mode: u16)
    -> Option<(u32, u32, u16)>
{
    let t = task?;
    let searchable = is_world_searchable_dir(is_dir, mode & 0o7777);
    let (uid, gid) = dump_owner(t.kthread, t.euid, t.egid, t.dumpable, searchable);
    Some((uid, gid, mode & !SUID_SGID))
}

/// Linux `pid_delete_dentry`: a dead task's per-pid dentries never reach the
/// LRU. Keeping them is what lets a RECYCLED pid inherit the previous task's
/// cached inode. # C: O(1)
pub fn delete_pid_dentry(task_alive: bool) -> bool { !task_alive }
