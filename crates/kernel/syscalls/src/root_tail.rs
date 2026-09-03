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
// The usercopy half of the iovec importer. Kernel-only by nature (it reads
// user memory); the RULES it applies live in `rwf` and are hosted-tested.
pub mod iov;
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
#[path = "dispatch/frame_order.rs"] pub mod dispatch_frame_order;
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
/// User-buffer layouts and chunking for ptrace's copy paths. Ungated so the
/// rules stay reachable from `cargo test`; the four call sites are whole-file
/// kernel-gated (`docs/53`).
#[path = "101_ptrace/user.rs"] pub mod s101_ptrace_user;
#[cfg(target_os = "oxide-kernel")]
#[path = "103_syslog.rs"] pub mod s103_syslog;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
extern crate std;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod fd_pair;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod socket_fd;

// Ungated hosted (not just under `cfg(test)`) because `sock_route::endpoint_of`
// classifies through its downcasts, and that classification is what the control
// slots act on.
#[cfg(not(target_os = "oxide-kernel"))]
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
// The receive copy-fault transaction: publication order and per-step fault
// rule, shared by every family and both batch layers.
#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod recv_txn;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "recvmsg/entry.rs"]
mod recvmsg_entry_hosted;
#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod send_user;

// Pure sockaddr encoders: compiled for BOTH the kernel and hosted tests, so
// every `*_getname` length/byte layout is provable under `cargo test` even
// though `net_sockaddr` (its user-memory marshalling) is kernel-only.
// The AF_PACKET setsockopt write SHAPE (per-option `optlen` contract, the
// cooked-socket refusal, the vnet-header coercion) — kernel + hosted, so the
// ABI is provable under `cargo test` while the slot stays an import shim.
mod packet_optshape;

mod sockaddr_encode;

// The `socketpair(2)` creation admission — kernel + hosted, so the family and
// type rules are provable under `cargo test` while the slot stays an ABI shim.
mod socketpair_spec;

// The `*_getname` DECISIONS (which socket field answers, which error a socket
// with no such name reports) — kernel + hosted, so `getsockname`/`getpeername`
// behaviour is provable under `cargo test` while the slots stay ABI shims.
mod sock_name;

// The fd-classification ladder the control syscalls share (EBADF before
// ENOTSOCK before a protocol's "no such operation") — kernel + hosted, so the
// order and the errnos are provable under `cargo test` while
// `048_shutdown`/`050_listen`/`043_accept`/`052_getpeername` stay ABI shims.
mod sock_route;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod namei_common {
    use alloc::string::String;

    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(_addr: u64) -> Result<String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
    pub fn read_user_path_allow_empty(_addr: u64) -> Result<String, i64> {
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
