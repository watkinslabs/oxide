// The `/proc/sys/kernel/` subtree.
//
// Split out of the tree manifest because `ctl.rs` was over the file-length cap:
// this is the largest branch and the one that grows whenever a subsystem gains
// a knob. Every leaf binds the same way it did inline — the split moves text,
// not policy.

use super::*;
use Node::{Dir, File};

/// The children of `Dir("kernel", ...)`. # C: n/a
pub const KERNEL_SYSCTLS: &[Node] = &[
        File("pid_max",               Int(32768, Some((1, 4_194_304)))),
        File("ngroups_max",           Const(b"65536\n")),
        File("cap_last_cap",          Const(b"40\n")),
        // The three utsname fields this subtree reports are DERIVED from the
        // one kernel-version owner, never re-typed: a reader comparing these
        // against `uname(2)` must not be able to tell them apart.
        File("osrelease",             Const(syscall::uts::PROC_SYS_OSRELEASE.as_bytes())),
        File("ostype",                Const(syscall::uts::PROC_SYS_OSTYPE.as_bytes())),
        File("version",               Const(syscall::uts::PROC_SYS_VERSION.as_bytes())),
        File("domainname",            StrHook(crate::hooks::domainname, crate::hooks::set_domainname)),
        File("threads-max",           Int(32768, Some((20, INT_MAX)))),
        File("printk",                Bytes(b"4\t4\t1\t7\n")),
        // Bound to the three tunables every BSD-process-accounting free-space
        // check reads (`fs::acct`), not a procfs-local copy: a dead cell here
        // would report a suspend threshold that no accounting write applies.
        File("acct",                  StrHook(crate::hooks::acct_parm, crate::hooks::set_acct_parm)),
        File("sched_rr_timeslice_ms", Int(100, Some((1, INT_MAX)))),
        // Bound to `aslr`'s live cell — the same value every exec reads when it
        // decides whether to randomise. A procfs-local copy would let this file
        // report a protection the loader is not applying (or the reverse), which
        // is the exact falsehood hardening scanners were being told before ASLR
        // existed. Linux registers this leaf with plain `proc_dointvec` and NO
        // extra1/extra2, so no bounds here either.
        File("randomize_va_space",    IntHook(get_randomize_va_space,
                                              set_randomize_va_space, None)),
        // Bound to the live value `perf_event_open` consults (`sched::perf_sw`),
        // not a procfs-local cell — a dead cell here would let userspace loosen
        // a gate the syscall never reads.
        File("perf_event_paranoid",   IntHook(get_perf_paranoid, set_perf_paranoid, Some((-1, 4)))),
        File("perf_event_max_sample_rate",
            IntHook(get_perf_sample_rate, set_perf_sample_rate, Some((1, INT_MAX)))),
        // Bound to the live cell `bpf(2)` consults before it lets an
        // unprivileged caller create a map or load a program, not a
        // procfs-local copy: a dead cell here would report the interface as
        // closed while it kept accepting unprivileged callers. Writing 1 is a
        // one-way latch and only the administrative capability may write at
        // all, so the setter answers EPERM where a bad value would be EINVAL.
        File("unprivileged_bpf_disabled",
                                      PermIntHook(get_unpriv_bpf_disabled,
                                                  set_unpriv_bpf_disabled,
                                                  Some(security::bpf::attr::UNPRIV_BPF_BOUNDS))),
        File("dmesg_restrict",        IntHook(get_dmesg_restrict, set_dmesg_restrict, Some((0, 1)))),
        File("kptr_restrict",         Int(0, Some((0, 2)))),
        File("modules_disabled",      IntHook(get_modules_disabled, set_modules_disabled, Some((1, 1)))),
        // Bound to the live cells ring creation consults, not a procfs-local
        // cell: a dead cell here would report io_uring as disabled while rings
        // kept being handed out. `io_uring_group` carries no bounds — a
        // negative gid is the legal "no group" value.
        File("io_uring_disabled",     IntHook(get_io_uring_disabled, set_io_uring_disabled,
                                              Some(syscall::io_uring_ctl::DISABLED_BOUNDS))),
        File("io_uring_group",        IntHook(get_io_uring_group, set_io_uring_group, None)),
        File("shm_rmid_forced",       IntHook(get_shm_rmid_forced, set_shm_rmid_forced,
                                              Some(ipc::sysv_shm::RMID_FORCED_BOUNDS))),
        File("hostname",              StrHook(crate::hooks::hostname, crate::hooks::set_hostname)),
        // core dump control (systemd-coredump / sysctl.d write these). Both
        // core_pattern and core_pipe_limit are bound to fs::coredump's live
        // cells — `write_for_current` honours the template, and the pipe
        // destination consults the cap before it starts a collector.
        File("core_pattern",          StrHook(crate::hooks::core_pattern, crate::hooks::set_core_pattern)),
        File("core_pipe_limit",       IntHook(crate::hooks::core_pipe_limit,
                                              crate::hooks::set_core_pipe_limit,
                                              Some((0, INT_MAX)))),
        File("core_uses_pid",         Int(1, Some((0, 1)))),
        File("sysrq",                 Int(16, Some((0, 511)))),
        // Linux's keys sysctl table registers the four per-uid key ceilings against
        // the LIVE `key_quota_*` variables `key_alloc` tests, each a
        // `proc_dointvec_minmax` over [1, INT_MAX], plus the persistent-keyring
        // window over [0, INT_MAX]. Bound to the key store's own accessors: a
        // procfs-local cell would let an admin raise a ceiling here and still
        // collect EDQUOT from `add_key(2)`.
        Dir("keys", &[
            File("maxkeys",       IntHook(crate::hooks::keyring::maxkeys,
                                          crate::hooks::keyring::set_maxkeys,
                                          Some(crate::hooks::keyring::KEY_QUOTA_BOUNDS))),
            File("maxbytes",      IntHook(crate::hooks::keyring::maxbytes,
                                          crate::hooks::keyring::set_maxbytes,
                                          Some(crate::hooks::keyring::KEY_QUOTA_BOUNDS))),
            File("root_maxkeys",  IntHook(crate::hooks::keyring::root_maxkeys,
                                          crate::hooks::keyring::set_root_maxkeys,
                                          Some(crate::hooks::keyring::KEY_QUOTA_BOUNDS))),
            File("root_maxbytes", IntHook(crate::hooks::keyring::root_maxbytes,
                                          crate::hooks::keyring::set_root_maxbytes,
                                          Some(crate::hooks::keyring::KEY_QUOTA_BOUNDS))),
            // Bound to the value `KEYCTL_GET_PERSISTENT` stamps on the keyring
            // it hands back, so shortening the window really does shorten the
            // life of the next persistent keyring handed out.
            File("persistent_keyring_expiry",
                                  IntHook(crate::hooks::keyring::persistent_expiry,
                                          crate::hooks::keyring::set_persistent_expiry,
                                          Some(crate::hooks::keyring::KEY_EXPIRY_BOUNDS))),
        ]),
        // Bound to the live cell `__ptrace_may_access`'s LSM tail consults,
        // not a procfs-local copy: a dead cell here would report a hardening
        // level that no attach path applies. Writes are one-way (the scope
        // may be raised, never lowered), which is why the setter is a hook
        // rather than a bounded `Int`.
        Dir("yama", &[
            File("ptrace_scope",      CheckedIntHook(get_ptrace_scope, set_ptrace_scope,
                                              Some((0, sched::yama::SCOPE_MAX as i64)))),
        ]),
];
