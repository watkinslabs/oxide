// Per-pid `/proc` file POLICY — Linux `fs/proc/base.c`: the `tgid_base_stuff`
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
