use super::*;

#[test]
fn address_space_and_execution_state_files_are_owner_only() {
    // Every one of these was mode 0444 before B1463, so any local user could
    // read another user's environment, auxv, syscall arguments and io counters.
    for name in ["environ", "auxv", "personality", "syscall", "stack", "io",
                 "mountstats", "pagemap"] {
        assert_eq!(pid_file_mode(name), MODE_RUSR, "{name} must be S_IRUSR");
    }
}

#[test]
fn world_readable_files_stay_world_readable() {
    for name in ["status", "stat", "statm", "cmdline", "limits", "maps",
                 "smaps", "cgroup", "mounts", "mountinfo", "wchan", "schedstat"] {
        assert_eq!(pid_file_mode(name), MODE_RUGO, "{name} is S_IRUGO in tgid_base_stuff");
    }
}

#[test]
fn writable_control_files_carry_their_write_bit() {
    for name in ["comm", "sched", "oom_score_adj", "loginuid", "uid_map",
                 "gid_map", "setgroups", "coredump_filter", "timens_offsets"] {
        assert_eq!(pid_file_mode(name), MODE_RUGO_WUSR, "{name} is S_IRUGO|S_IWUSR");
    }
    assert_eq!(pid_file_mode("timerslack_ns"), MODE_RUGO_WUGO);
    assert_eq!(pid_file_mode("clear_refs"), 0o200, "write-only");
}

#[test]
fn directory_modes_match_the_linux_table() {
    assert_eq!(pid_file_mode("fd"), MODE_DIR_RUSR, "S_IRUSR|S_IXUSR");
    assert_eq!(pid_file_mode("ns"), MODE_DIR_NS, "S_IRUSR|S_IXUGO");
    assert_eq!(pid_file_mode("fdinfo"), MODE_DIR_RUGO);
    assert_eq!(pid_file_mode("task"), MODE_DIR_RUGO);
    assert_eq!(pid_file_mode("attr"), MODE_DIR_RUGO);
}

#[test]
fn the_ptrace_gated_set_is_exactly_the_state_leaking_entries() {
    for name in ["environ", "auxv", "maps", "smaps", "personality", "syscall",
                 "stack", "io", "mem", "pagemap"] {
        assert!(needs_ptrace_gate(name), "{name} needs ptrace_may_access");
    }
    for name in ["status", "stat", "statm", "cmdline", "comm", "limits",
                 "cgroup", "mounts", "oom_score", "wchan"] {
        assert!(!needs_ptrace_gate(name), "{name} is not ptrace-gated in Linux");
    }
}

#[test]
fn a_kernel_threads_proc_nodes_are_owned_by_root() {
    assert_eq!(dump_owner(true, 1000, 1000, SUID_DUMP_USER, false), (0, 0));
    assert_eq!(dump_owner(true, 1000, 1000, SUID_DUMP_USER, true), (0, 0));
}

#[test]
fn a_dumpable_user_task_owns_its_own_proc_nodes() {
    assert_eq!(dump_owner(false, 1000, 100, SUID_DUMP_USER, false), (1000, 100));
    assert_eq!(dump_owner(false, 1000, 100, SUID_DUMP_USER, true), (1000, 100));
}

#[test]
fn the_dump_owner_exemption_is_the_world_searchable_directory_mode() {
    assert!(is_world_searchable_dir(true, MODE_DIR_RUGO), "S_IFDIR|S_IRUGO|S_IXUGO");
    assert!(!is_world_searchable_dir(true, MODE_DIR_RUSR), "fd/ is owner-only, not exempt");
    assert!(!is_world_searchable_dir(true, MODE_DIR_NS), "ns/ is 0511, not exempt");
    assert!(!is_world_searchable_dir(false, MODE_DIR_RUGO), "a regular file is never exempt");
}

#[test]
fn a_non_dumpable_task_hands_its_files_but_not_its_directory_to_root() {
    // A setuid-root binary run by uid 1000 becomes non-dumpable at exec. Its
    // per-pid FILES must become root-owned so the spawning user cannot read
    // them; the per-pid DIRECTORY keeps the euid so `stat /proc/<pid>` still
    // answers the question procps has always asked of it.
    const SUID_DUMP_DISABLE: u8 = 0;
    assert_eq!(dump_owner(false, 0, 0, SUID_DUMP_DISABLE, false), (0, 0));
    assert_eq!(dump_owner(false, 1000, 1000, SUID_DUMP_DISABLE, false), (0, 0),
               "files of a non-dumpable task are root-owned");
    assert_eq!(dump_owner(false, 1000, 1000, SUID_DUMP_DISABLE, true), (1000, 1000),
               "the per-pid directory keeps the task's euid");
}

/// `S_IFDIR` — the type bits `revalidate_pid_inode` must preserve.
const S_IFDIR: u16 = 0o040000;

fn user_task(euid: u32) -> Option<TaskOwner> {
    Some(TaskOwner { kthread: false, euid, egid: euid, dumpable: SUID_DUMP_USER })
}

#[test]
fn a_cached_fd_directory_follows_the_task_across_a_setuid() {
    // The failure this hook exists for: a process populates its own
    // `/proc/<pid>/fd` dentry while still root (systemd closes inherited fds by
    // walking that directory), then drops to uid 1000 and execs the per-user
    // manager, which walks it again. Serving the cached root-owned inode makes
    // the task's own 0500 fd directory unreadable to it — EACCES, and the user
    // manager exits 1 before it can reach its notify socket.
    let mode = S_IFDIR | MODE_DIR_RUSR;
    assert_eq!(revalidate_pid_inode(user_task(0), true, mode), Some((0, 0, mode)));
    assert_eq!(revalidate_pid_inode(user_task(1000), true, mode), Some((1000, 1000, mode)),
               "re-stamped from the task's CURRENT euid, not the cached one");
}

#[test]
fn revalidation_reports_a_dead_task_stale() {
    // Linux `pid_revalidate` returns 0 with no task, which drops the dentry —
    // the only thing stopping a recycled pid from inheriting the previous
    // task's cached per-pid inodes.
    assert_eq!(revalidate_pid_inode(None, true, S_IFDIR | MODE_DIR_RUSR), None);
    assert_eq!(revalidate_pid_inode(None, false, MODE_RUGO), None);
}

#[test]
fn revalidation_keeps_the_table_mode_and_clears_the_setid_bits() {
    // `pid_update_inode` moves ownership and clears S_ISUID|S_ISGID; the
    // `tgid_base_stuff` mode column is not the dcache's to rewrite.
    let (_, _, mode) = revalidate_pid_inode(user_task(1000), false, MODE_RUGO_WUSR).unwrap();
    assert_eq!(mode, MODE_RUGO_WUSR, "table mode survives revalidation");
    let (_, _, mode) = revalidate_pid_inode(user_task(1000), false, 0o6444).unwrap();
    assert_eq!(mode, 0o444, "S_ISUID|S_ISGID cleared");
}

#[test]
fn revalidation_applies_the_non_dumpable_clamp_per_node() {
    // Same task, two nodes: the world-searchable per-pid directory keeps the
    // euid, everything else goes to root once the task stopped being dumpable.
    let t = || Some(TaskOwner { kthread: false, euid: 1000, egid: 1000, dumpable: 0 });
    assert_eq!(revalidate_pid_inode(t(), true, S_IFDIR | MODE_DIR_RUGO),
               Some((1000, 1000, S_IFDIR | MODE_DIR_RUGO)));
    assert_eq!(revalidate_pid_inode(t(), true, S_IFDIR | MODE_DIR_RUSR),
               Some((0, 0, S_IFDIR | MODE_DIR_RUSR)));
    assert_eq!(revalidate_pid_inode(t(), false, MODE_RUSR), Some((0, 0, MODE_RUSR)));
}

#[test]
fn only_a_dead_tasks_dentries_are_killed_on_the_final_put() {
    assert!(delete_pid_dentry(false), "a dead task's dentry never reaches the LRU");
    assert!(!delete_pid_dentry(true), "a live task's dentry stays cached");
}
