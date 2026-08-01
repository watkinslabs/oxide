// Glue between per-arch syscall asm stub and dispatch table per `15§4`.

#![no_std]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;

mod membarrier;
mod affinity_abi;
mod getdents_abi;
mod net_errno;
pub mod arch_prctl_abi;
pub mod obsolete;
// Slots refused with the errno Linux returns when the backing CONFIG is unset
// (modify_ldt, iopl, ioperm, kexec_load, kexec_file_load). Outside the
// kernel-only cfg so the pinned slot set is actually unit-tested.
pub mod unconfigured;
mod access_cred;
mod lsm;
mod pkey;
// User-buffer range coverage, the decision half of `userbuf`'s access checks.
// Ungated because `userbuf.rs` is kernel-only: the walk that replaced a
// per-PAGE loop with a per-VMA one is exactly the kind of bound that has to be
// tested, having wedged a CPU for 300+ s with interrupts masked (B1476).
pub mod uaccess_range;
pub mod secretmem;
// execve(2) 59: the AT_RANDOM auxv block. Kernel-gated slot files can't be
// tested, and this is what glibc's stack canary + pointer guard come from.
pub mod auxrandom;
// execve(2) 59 / execveat(2) 322: the credential transition — setuid/setgid
// honouring and its suppression rules, the capability sets, AT_SECURE and
// dumpability. Same reason as `auxrandom`: the slot files are kernel-gated, and
// this is the one decision in exec that must never ship untested.
pub mod exec_creds;
// swapon(2) 167: the `swap_flags` decode + its EINVAL-before-EPERM order.
// futimesat(2) 261 / utimes(2) 235: the `struct timeval[2]` decode. Both slot
// files are kernel-gated, so the decisions live here where the hosted suite
// can reach them (docs/53, CLAUDE.md phantom-test rule).
pub mod swap_abi;
// vhangup(2) 153 + the TIOCNOTTY ioctl share ONE controlling-terminal
// resolver so they cannot disagree about which tty the caller holds.
pub mod tty_hangup;
pub mod utimes_abi;
pub mod utimensat_abi;
// ustat(2) 136: `struct ustat` wire layout. sysfs(2) 139: the option/index
// query over the filesystem-type registry. remap_file_pages(2) 216 /
// fadvise64(2) 221 / mlock2(2) 325: their admission ladders. All five slot
// files are kernel-gated, so the decisions live here where the hosted suite
// can reach them (docs/53, CLAUDE.md phantom-test rule).
pub mod ustat_abi;
pub mod sysfs_query;
pub mod remap_policy;
pub mod fadvise_policy;
pub mod mlock_policy;
// name_to_handle_at(2) 303 / open_by_handle_at(2) 304: the `struct file_handle`
// ABI, the AT_HANDLE_* flag masks and both admission ladders.
pub mod handle_policy;
// openat2(2) 437: the `struct open_how::resolve` word — its validation and its
// mapping onto `LookupFlags` for BOTH walk phases. `257_openat.rs` is
// kernel-gated, and dropping a RESOLVE_* bit on the O_CREAT parent walk is a
// sandbox escape, so the decision lives here where the hosted suite reaches it.
pub mod openat2_resolve;
// clone(2) 56 / fork(2) 57 / vfork(2) 58 / clone3(2) 435: the `CLONE_*` bit
// names, the versioned `struct clone_args` layout and BOTH entry points'
// validation ladders. The slot files are kernel-gated, and every rule here is
// observable only as an errno or an errno ORDER, so it lives where the hosted
// suite reaches it (docs/53, CLAUDE.md phantom-test rule).
pub mod clone_abi;
pub mod sched_policy;
pub mod syscall_rollback;
pub mod sched_attr;
pub mod ioprio;
// getpriority/setpriority (140/141) + ioprio_set/ioprio_get (251/252) share one
// which/who target-set walk. Its RULES — the `who == 0` aliases, the
// user-namespace uid mapping of `who`, and the pid-namespace visibility test
// that keeps a PRIO_USER sweep inside the caller's namespace — live here,
// ungated, because the live walk in `priority_common` is kernel-only.
pub mod priority_target;
// rename(2)/renameat2(2): the `filename_renameat2` errno LADDER (EXDEV before
// EBUSY, the NOREPLACE EEXIST override, the ancestor-trap EINVAL/ENOTEMPTY
// split, trailing-slash ENOTDIR) — order is the whole contract, so it lives
// outside the kernel-only slot files where it can be tested.
pub mod path_ops_policy;
pub mod rename_policy;
// Clock syscall decision order: compiled into the kernel AND the hosted test
// build, because the EINVAL/EFAULT/EPERM sequencing is what the tests assert.
pub mod clock_policy;
// adjtimex / clock_adjtime: the `struct __kernel_timex` wire layout and the
// two syscalls' differing copy-back and clock-admission rules. Both compiled
// hosted for the same reason as `clock_policy`.
pub mod timex_abi;
pub mod timex_policy;
// pivot_root: the `path_pivot_root()` check ladder, whose ORDER is the only
// observable part of a rejected call.
pub mod pivot_root_policy;
// fsconfig(2): the per-command `_key`/`_value`/`aux` admission switch of
// `SYSCALL_DEFINE5(fsconfig)`, including the EOPNOTSUPP-not-EINVAL default and
// SET_FD's non-negative-aux rule. `431_fsconfig.rs` is kernel-gated.
pub mod fsconfig_abi;
// mount(2)'s flag-word preamble: the MS_MGC_VAL magic strip and the MS_NOUSER
// reject, whose ORDER is load-bearing (the magic value CONTAINS MS_NOUSER).
pub mod mount_flags_policy;
// The new mount API's flag words. Each rejected call reports EINVAL from a rule
// that is NOT a plain unknown-bit mask (open_tree's AT_RECURSIVE-needs-CLONE,
// move_mount's BENEATH-xor-SET_GROUP), and each accepted call SELECTS the walk
// (follow/automount/empty) — none of which a kernel-gated slot file can test.
pub mod open_tree_policy;
pub mod move_mount_policy;
pub mod fspick_policy;
// io_uring identity: which description is a ring, and each caller's errno when
// it is not. Ungated so it is testable — `io_uring.rs` is kernel-only.
pub mod io_uring_identity;
// acct (163): which pid numbering each target pid namespace's accounting
// record carries. Ungated so the mapping is testable — `acct_exit.rs` is
// kernel-only.
pub mod acct_ns;
mod fcntl_dup;
mod exec_time;
mod pidfd_signal_policy;
mod kill_policy;
mod perm_common;
#[cfg(target_os = "oxide-kernel")]
mod clone_cgroup;
// setrlimit/getrlimit/prlimit64 (097/160/302): the `do_prlimit` errno mapping
// plus the hosted tests for the ladder all three share.
pub mod rlimit_policy;
// sethostname/setdomainname (170/171): the `ns_capable`-then-length ordering
// and `__NEW_UTS_LEN` window, compiled hosted so the ORDER is unit-tested.
pub mod uts_policy;
// unshare (272): Linux `check_unshare_flags` + the implied-flag expansion and
// the capability the requested namespace set needs.
pub mod unshare_policy;
// pselect6/ppoll (270/271) ABI rules: the event-loop core every glibc
// `poll(2)`/`select(2)` lands on, so the rules compile hosted and are
// unit-tested without a boot.
pub mod pselect_ppoll;
// `sys_ioctl` (16) ABI constants and the `do_vfs_ioctl`-vs-`f_op->unlocked_ioctl`
// ownership rule. Ungated: the `016_ioctl` module itself is kernel-target-only,
// so its decision logic has to live where tests can reach it.
pub(crate) mod ioctl_uapi;
pub(crate) mod ioctl_owner;
// tkill(2)/tgkill(2) share one `do_tkill`; the pid/tgid admission rules are the
// only user-visible part of a rejected call, so they compile hosted.
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod tkill_common;
// restart_syscall(2): the restart-block continuation table. Compiled hosted so
// the dispatch selection is unit-tested without a live task.
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "219_restart_syscall.rs"] pub mod s219_restart_syscall;

// madvise(2): compile its pure VMA/advice engine hosted so the canonical
// PAGEOUT dispatch tests do not exist only as path-included phantom coverage.
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "028_madvise.rs"]
mod s028_madvise;

// memfd_create (319): the `sanitize_flags` EINVAL/EACCES ladder plus the seal
// word / inode mode `memfd_alloc_file` derives. execveat (322): the AT_* flag
// mask, the empty-path ENOENT rule, the dirfd-base decision and the `may_open`
// file-type verdict. Both outside their kernel-only slot files so the rules
// that decide a rejected call are unit-tested hosted.
pub mod memfd_flags;
pub mod fcntl_seal;
pub mod execveat_at;

#[cfg(target_os = "oxide-kernel")]
include!("kernel_body.rs");

#[cfg(any(target_os = "oxide-kernel", test))]
mod tcp_info;

// Linux `struct stat` encoder: the byte offsets and the signed `st_*time` /
// unsigned `st_*time_nsec` split are the whole observable contract, so it
// compiles hosted too. Declared here rather than in `kernel_body.rs` because a
// `#[cfg(test)] mod tests` under that gate compiles out silently — which is
// exactly what happened to its two `write_new_stat_*_bytes` helpers.
#[cfg(any(target_os = "oxide-kernel", test))]
mod stat_common;

// io_uring(2) 425/426/427: the `struct io_uring_params` wire form, the setup
// flag/entries ladder, the ring-region geometry and the register-opcode
// ladder. The three slot files AND `io_uring.rs` are kernel-gated, so every
// decision left in them is invisible to `cargo test` (CLAUDE.md phantom-test
// rule); the slots parse/validate/call/encode around this module (docs/53).
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "io_uring/abi/mod.rs"]
pub mod io_uring_abi;

// libaio(2) 206-210/333: the `struct iocb`/`struct io_event`/`struct aio_ring`
// wire forms, io_setup's nr_events rounding + fs.aio-max-nr admission, the
// submit validation ladder and the completion-ring index arithmetic. `aio.rs`
// and its children are kernel-gated, so every decision left in them is
// invisible to `cargo test` (CLAUDE.md phantom-test rule); the slots
// parse/validate/call/encode around this module (docs/53).
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "aio/abi/mod.rs"]
pub mod aio_abi;

// statfs(2) wire encoding and uname(2) personality overrides: pure ABI logic,
// compiled into the kernel and into the hosted test build so the struct layout
// and the Linux override rules are unit-testable without a boot.
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod statfs_abi;
// statx(2) wire layout + the EINVAL ladder and its fd-vs-path asymmetry. Not
// target-gated: the 256-byte offsets and the validation ORDER are the whole
// observable contract and must be unit-tested (`08` phantom-test rule).
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod statx_abi;
// preadv2/pwritev2 RWF_* validation + the 64-bit `pos_from_hilo` rule. Hosted
// for the same reason: an arch-conditional offset formula that is wrong on
// x86_64 is invisible to any test that lives inside the gated slot file.
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod rwf;
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "063_uname/release.rs"] pub mod uname_release;
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "099_sysinfo/abi.rs"] pub mod sysinfo_abi;

#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "103_syslog/decide.rs"] pub mod s103_syslog_decide;
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod kcmp_abi;
pub mod setns_flags;
#[path = "101_ptrace/uapi.rs"] pub mod s101_ptrace_uapi;
/// `syscall_trace_enter`'s phase ORDER. Declared here rather than from
/// `dispatch/mod.rs`, which is kernel-gated: a `#[cfg(test)]` block inside a
/// gated module compiles away silently and its tests never run.
#[path = "dispatch/entry_order.rs"] pub mod dispatch_entry_order;
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "101_ptrace/decide.rs"] pub mod s101_ptrace_decide;
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "101_ptrace/perm.rs"] pub mod s101_ptrace_perm;
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "101_ptrace/regs.rs"] pub mod s101_ptrace_regs;
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "101_ptrace/event.rs"] pub mod s101_ptrace_event;
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "101_ptrace/sysinfo.rs"] pub mod s101_ptrace_sysinfo;
#[cfg(any(target_os = "oxide-kernel", test))]
#[path = "101_ptrace/sigstop.rs"] pub mod s101_ptrace_sigstop;
#[cfg(target_os = "oxide-kernel")]
#[path = "103_syslog.rs"] pub mod s103_syslog;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
extern crate std;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod fd_pair;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod socket_fd;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod net_common;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod name_copyout;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "time_common.rs"]
mod time_common;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod io_uring_sqe;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod packet_mmap;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod recv_user;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod recv_control;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "recvmsg/entry.rs"]
mod recvmsg_entry_hosted;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod send_user;

// Pure sockaddr encoders: compiled for BOTH the kernel and hosted tests, so
// every `*_getname` length/byte layout is provable under `cargo test` even
// though `net_sockaddr` (its user-memory marshalling) is kernel-only.
mod sockaddr_encode;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod socket_control_tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod getdents_debug_tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod poll_ownership_tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod fcntl_dup_tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "recvmsg/vsock.rs"]
mod vsock_recv_shutdown_boundary;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "016_ioctl/netns_fd.rs"]
mod siocgskns_fd;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "054_setsockopt/multicast.rs"]
mod mcast_set_boundary;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "054_setsockopt/packet_abi.rs"]
mod packet_membership_abi;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "055_getsockopt/packet_abi.rs"]
mod packet_get_abi;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "055_getsockopt/out.rs"]
mod out;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "055_getsockopt/multicast.rs"]
mod mcast_get_boundary;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod namei_common {
    use alloc::string::String;

    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(_addr: u64) -> Result<String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod pathresolve {
    pub fn resolve_path_raw(_raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        Err(vfs::VfsError::Enoent)
    }
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "179_quotactl.rs"] pub mod s179_quotactl;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "443_quotactl_fd.rs"] pub mod s443_quotactl_fd;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "470_listns.rs"] pub mod s470_listns;
