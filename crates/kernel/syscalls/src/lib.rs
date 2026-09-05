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
#[cfg(all(not(target_os = "oxide-kernel"), not(test)))]
extern crate std;

mod membarrier;
mod pe_exec;
mod affinity_abi;
mod getdents_abi;
mod net_errno;
// Receive admission + protocol selection: kernel + hosted, so the rule that no
// receive reaches a protocol unadmitted is provable under `cargo test` while
// `recvmsg::dispatch` stays a pin-and-route shim.
mod recv_admit;
pub mod netlink_getsockopt_policy;
pub mod mmsg_batch;
// The one owner of "which message ABI does this call speak" plus both shapes.
pub mod msg_layout;
pub mod nt_dispatch;
mod nt_system_info;
mod nt_process_parameters;
mod nt_process_policy;
mod nt_directory_abi;
pub(crate) mod nt_file_policy;
mod nt_file_async_policy;
mod nt_file_scatter_policy;
mod nt_file_gather_policy;
mod nt_file_volume_abi;
mod nt_loader_dir_policy;
pub(crate) mod nt_file_lock_policy;
pub(crate) mod nt_registry_policy;
pub(crate) mod nt_directory_notify_policy;
mod nt_path;
mod nt_path_type;
mod nt_image;
mod nt_dos83;
#[cfg(target_os = "oxide-kernel")]
mod nt_heap_lock;
#[cfg(target_os = "oxide-kernel")]
mod nt_oem;
#[cfg(target_os = "oxide-kernel")]
mod nt_exec;
#[cfg(target_os = "oxide-kernel")]
mod nt_file;
#[cfg(target_os = "oxide-kernel")]
mod nt_file_scatter;
#[cfg(target_os = "oxide-kernel")]
mod nt_file_gather;
#[cfg(target_os = "oxide-kernel")]
mod nt_file_volume;
#[cfg(target_os = "oxide-kernel")]
mod nt_file_lock;
#[cfg(target_os = "oxide-kernel")]
mod nt_duplicate;
#[cfg(target_os = "oxide-kernel")]
mod nt_process_handles;
mod nt_process_vm_counters;
mod nt_process_image_policy;
mod nt_process_command_line;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
mod nt_process_create;
mod nt_process_memory;
mod nt_process_memory_policy;
mod nt_vulkan_policy;
mod nt_system_time;
#[cfg(target_os = "oxide-kernel")]
mod nt_timer;
#[cfg(target_os = "oxide-kernel")]
mod nt_completion;
#[cfg(target_os = "oxide-kernel")]
mod nt_signal_wait;
#[cfg(target_os = "oxide-kernel")]
mod nt_token;
#[cfg(target_os = "oxide-kernel")]
mod nt_priority;
mod nt_thread_info_policy;
#[cfg(target_os = "oxide-kernel")]
mod nt_registry;
#[cfg(target_os = "oxide-kernel")]
mod nt_directory_notify;
#[cfg(target_os = "oxide-kernel")]
mod nt_wine_window;
mod nt_wine_unix;
mod nt_wine_unwind;
#[cfg(target_os = "oxide-kernel")]
mod nt_heap;
#[cfg(target_os = "oxide-kernel")]
mod nt_loader_dir;
#[cfg(target_os = "oxide-kernel")]
mod nt_loader_proc;
#[cfg(target_os = "oxide-kernel")]
mod nt_directory;
#[cfg(target_os = "oxide-kernel")]
mod nt_actctx;
#[cfg(target_os = "oxide-kernel")]
mod nt_env;
#[cfg(target_os = "oxide-kernel")]
mod nt_threadpool;
#[cfg(target_os = "oxide-kernel")]
mod nt_user_stack;
#[cfg(target_os = "oxide-kernel")]
mod nt_capability;
#[cfg(target_os = "oxide-kernel")]
mod nt_exists;
#[cfg(target_os = "oxide-kernel")]
mod nt_search_path;
#[cfg(target_os = "oxide-kernel")]
mod nt_acl;
#[cfg(target_os = "oxide-kernel")]
mod nt_apiset;
#[cfg(target_os = "oxide-kernel")]
mod nt_atom;
#[cfg(target_os = "oxide-kernel")]
mod nt_power;
#[cfg(target_os = "oxide-kernel")]
mod nt_fls;
#[cfg(target_os = "oxide-kernel")]
mod nt_tls;
#[cfg(target_os = "oxide-kernel")]
mod nt_format;
#[cfg(target_os = "oxide-kernel")]
mod nt_window;
#[cfg(target_os = "oxide-kernel")]
mod nt_gdi;
#[cfg(target_os = "oxide-kernel")]
mod nt_vulkan;
#[cfg(target_os = "oxide-kernel")]
mod nt_unwind;
#[cfg(target_os = "oxide-kernel")]
mod nt_exception;
mod nt_nls;
#[cfg(target_os = "oxide-kernel")]
mod nt_memory_lock;
#[cfg(target_os = "oxide-kernel")]
mod nt_rtl;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
mod nt_rtl_xstate;
mod nt_bitmap;
mod nt_unicode;
mod nt_context;
#[cfg(any(not(target_os = "oxide-kernel"), target_arch = "x86_64"))]
mod nt_context_image;
mod nt_sid;
#[cfg(target_os = "oxide-kernel")]
mod nt_rtl_ansi;
#[cfg(target_os = "oxide-kernel")]
mod nt_debug;
#[cfg(target_os = "oxide-kernel")]
mod nt_rtl_integer;
#[cfg(target_os = "oxide-kernel")]
mod nt_critical;
#[cfg(target_os = "oxide-kernel")]
mod nt_printf;
#[path = "nt_security.rs"]
mod nt_security;
#[path = "nt_time.rs"]
mod nt_time;
mod nt_time_common;
mod nt_yield;
mod nt_wine_timeout;
#[cfg(target_os = "oxide-kernel")]
mod nt_object_query;
#[cfg(target_os = "oxide-kernel")]
mod nt_sync;
#[cfg(target_os = "oxide-kernel")]
mod nt_mutant;
mod nt_semaphore;
#[cfg(target_os = "oxide-kernel")]
mod nt_job;
pub mod arch_prctl_abi;
// `modify_ldt(2)` decision core: descriptor packing, `user_desc` decode, the
// sub-function table and the write ladder. Ungated because the slot file is
// kernel-only and one wrong bit in the packing is a silent privilege bug.
pub mod ldt_abi;
pub mod obsolete;
// `kexec_load`/`kexec_file_load` ABI edge: errno mapping, array sizing, the
// pinned slot numbers and their aarch64 routes. Ungated because both slot
// files are kernel-only, so tests written inside them would never run.
pub mod kexec_abi;
pub mod power_errno;
mod access_cred;
// Stale-handle retry rule shared by every path-based syscall. Ungated because
// the `*at` resolution layer that applies it is kernel-only, and an unbounded
// retry is the failure mode the rule exists to prevent.
pub mod estale_retry;
mod cachestat;
// `process_mrelease`'s "is this mm really about to be freed" ladder. Ungated
// because the slot file is kernel-only and this is the entire safety argument
// for letting one process tear down another's memory.
pub mod process_mrelease;
mod lsm;
mod pkey;
// The network-interface ioctl shim's decisions: which commands exist, whether
// each reads or changes device state, the ABI sizes it copies, and whether a
// named user range is usable. Ungated because `siocgif.rs` is kernel-only, so
// the twelve cases written beside it had never compiled once.
#[path = "siocgif/decide.rs"]
pub(crate) mod siocgif_decide;
// The live SIOC* adapter is kernel-gated because its copy boundary uses the
// exception-table uaccess shim. Include the exact production module in hosted
// tests as well: its tests use ordinary stack buffers, and this makes a
// missing production entry point fail the hosted build instead of silently
// reporting five decision-only cases.
#[cfg(test)]
#[path = "siocgif/hosted.rs"]
mod siocgif_hosted;
// The vDSO image's dynamic-symbol walk. Ungated because `vdso.rs` is
// kernel-only AND its one case carried an aarch64 arch gate on top, so it
// could never have compiled in any build that runs tests.
pub(crate) mod vdso_elf;
mod sigaltstack_abi;
// User-buffer range coverage, the decision half of `userbuf`'s access checks.
// Ungated because `userbuf.rs` is kernel-only: the walk that replaced a
// per-PAGE loop with a per-VMA one is exactly the kind of bound that has to be
// tested, having wedged a CPU for 300+ s with interrupts masked (B1476).
pub mod uaccess_range;
// uretprobe(2) 335 / uprobe(2) 336: what each kernel-injected slot owes a
// caller that did not arrive through a uprobe trampoline. Ungated because both
// slot files are kernel-only, and the two answers differ in a way a userspace
// feature probe reads directly.
pub mod uprobe_abi;
pub mod secretmem;
// execve(2) 59: the AT_RANDOM auxv block. Kernel-gated slot files can't be
// tested, and this is what glibc's stack canary + pointer guard come from.
pub mod auxrandom;
// execve(2) 59 / execveat(2) 322: the credential transition — setuid/setgid
// honouring and its suppression rules, the capability sets, AT_SECURE and
// dumpability. Same reason as `auxrandom`: the slot files are kernel-gated, and
// this is the one decision in exec that must never ship untested.
pub mod exec_creds;
pub mod exec_drain;
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
// perf side-band records (`PERF_RECORD_MMAP`/`COMM`/`FORK`/`EXIT`): the gather
// the mmap/exec/clone/exit slots perform before calling the `fs::perf` work fn.
// Ungated so the split it performs on `st_dev` is hosted-testable; every slot
// that calls it is kernel-gated (CLAUDE.md phantom-test rule).
pub mod perf_sideband;
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
// open(2) 2 / openat(2) 257 / openat2(2) 437: the `O_*` bit names plus the
// pre-resolution flag/mode normalisation ladder shared by all three, and the
// decode of an open's flag word into the `may_open` flag rungs. `257_openat.rs`
// and `open_common.rs` are kernel-gated, and every rule here is observable only
// as an errno or an errno ORDER, so it lives where the hosted suite reaches it.
pub mod open_flags;
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
// fsconfig(2) stage two: the user-memory copy-in ORDER and its per-stage errno,
// behind a `UserCopy` trait so the EFAULT rungs are reachable from a hosted test.
pub mod fsconfig_fetch;
// fsmount(2): the flag words, the privilege they SELECT (which differs under
// FSMOUNT_NAMESPACE), and the two post-creation superblock checks.
pub mod fsmount_abi;
// `mount_capable`: the ONE predicate mount(2) and fsconfig(CMD_CREATE) share for
// "who may create a superblock of this type", and the only rung of either whose
// answer depends on the caller's user namespaces.
pub mod mount_capable;
// The VfsError -> negative-errno table. Ungated and at the crate root because
// every ungated decision module that reports a VFS failure needs it; the
// kernel-only `namei_common` re-exports THIS one rather than owning a copy.
#[path = "namei_common/errno.rs"]
pub mod vfs_errno;
// mount(2)'s new-superblock arm: resolve the fstype, admit the option string,
// test `mount_capable`, run the visibility gate, graft — or report the honest
// errno. Ungated and LINKED (it used to live under the `target_os`-gated
// `fsmount_common`, where `cargo test` compiled none of it and the tests reached
// it by `#[path]`-including the file, so a break in the module the kernel
// actually links could not turn any of them red).
pub mod mount_dispatch;
// The parameter tables of the pseudo-filesystems `fsmount_common::registry`
// builds from the generic tree, and the stamp that puts a mount's `uid=`/`gid=`
// /`mode=` on the root it created. Ungated and LINKED for the same reason as
// `mount_dispatch`: `registry.rs` is `target_os`-gated, so a table declared
// there is compiled out of `cargo test` and no test could turn red on it.
#[path = "fsmount_common/pseudo_params.rs"]
pub mod fsmount_pseudo_params;
// mount(2)'s flag-word preamble: the MS_MGC_VAL magic strip and the MS_NOUSER
// reject, whose ORDER is load-bearing (the magic value CONTAINS MS_NOUSER).
pub mod mount_flags_policy;
// The new mount API's flag words. Each rejected call reports EINVAL from a rule
// that is NOT a plain unknown-bit mask (open_tree's AT_RECURSIVE-needs-CLONE,
// move_mount's BENEATH-xor-SET_GROUP), and each accepted call SELECTS the walk
// (follow/automount/empty) — none of which a kernel-gated slot file can test.
pub mod open_tree_policy;
// The idmap half of the shared `struct mount_attr` block: which of the two
// syscalls may REMOVE or REPLACE a mount's idmap, and when the `userns_fd`
// field is read at all. Ungated so it is testable — both slots are kernel-only.
pub mod mount_attr_abi;
pub mod mount_idmap_policy;
// statmount(2)/listmount(2) ABI: the request struct's size admission, the
// STATMOUNT_* field-mask space, the namespace-admission ladder, and the
// `struct statmount` writer. Ungated so all of it is testable — both slots are
// kernel-only.
pub mod statmount_abi;
// Shared statmount/listmount request plumbing; scheduler/nsfs facts sit behind
// its one cfg-selected child so the hosted harness can drive both slots.
pub mod statmount_target;
// Slots 457/458 are ungated: with the scheduler/nsfs facts isolated behind
// `statmount_target`'s cfg-selected child, both syscall bodies compile hosted
// and are driven end-to-end against a real fixture mount tree.
#[path = "457_statmount.rs"] pub mod s457_statmount;
#[path = "458_listmount.rs"] pub mod s458_listmount;
pub mod move_mount_policy;
pub mod fspick_policy;
// io_uring identity: which description is a ring, and each caller's errno when
// it is not. Ungated so it is testable — `io_uring.rs` is kernel-only.
pub mod io_uring_identity;
// External io_uring command storage: who owns it, what keeps it alive across a
// task hand-off, and which caller runs the one terminal completion. Ungated so
// the ordering is testable — `io_uring/linux_cmd.rs` is kernel-only.
pub mod io_uring_cmd_life;
// acct (163): which pid numbering each target pid namespace's accounting
// record carries. Ungated so the mapping is testable — `acct_exit.rs` is
// kernel-only.
pub mod acct_ns;
// pidfd ioctl (016 on a pidfd): the pidfs command vocabulary, the fixed vs
// extensible match rules and the struct-length gate on the result mask.
// Ungated so the ABI is unit-tested — `pidfd.rs` is kernel-only.
pub mod pidfs_ioctl;
mod fcntl_dup;
mod exec_time;
mod pidfd_signal_policy;
mod kill_policy;
mod perm_common;
// Fork/native-task cgroup commit boundary stays hosted so lifecycle ordering
// is exercised rather than hidden behind the kernel target.
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
// The ioctl stage's caller-memory accessors and the ABI offsets/bounds they
// use. Same reason for being ungated, plus one of its own: a raw dereference of
// a caller address has no exception-table fixup, so every one of them belongs
// on the fault-recovering usercopy this module wraps.
pub(crate) mod ioctl_user;
pub(crate) mod user_mem;
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
// `mmap(2)`'s huge-page decisions (granule selection, length rounding, the
// `MAP_HUGETLB`-on-an-ordinary-file contradiction), outside the kernel-only
// slot file so every one of them is unit-tested hosted.
pub mod mmap_huge;
pub mod fcntl_seal;
// fcntl F_GETDELEG/F_SETDELEG (1039/1040): the `struct delegation` wire form
// and its reserved-field validation, outside the kernel-only slot file.
pub mod fcntl_deleg;
// fcntl command numbers (one owner) + the `O_PATH` descriptor admission gate.
pub mod fcntl_cmds;
// Sleeping half of a delegation break, installed into the VFS at boot.
#[cfg(target_os = "oxide-kernel")]
pub mod deleg_break;
// fcntl's lease/delegation commands, split from the 072 slot file for the
// file cap; ABI shim only, every decision lives in the VFS lease policy.
#[cfg(target_os = "oxide-kernel")]
mod fcntl_lease;
pub mod execveat_at;
#[cfg(target_os = "oxide-kernel")]
include!("kernel_body.rs");
#[cfg(any(target_os = "oxide-kernel", test))]
mod tcp_info;
// `TCP_ZEROCOPY_RECEIVE`'s receive window. The window object and the socket
// `mmap(2)` admission carry no target gate so their tests compile hosted; only
// the option's copy-in/copy-out shim under it is kernel-only.
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod tcp_zerocopy;
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

include!("root_tail.rs");
