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
