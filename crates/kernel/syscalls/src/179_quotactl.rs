// 179 quotactl — targeted/classic quota syscall shim.
//
// Linux `quotactl(unsigned cmd, const char *special, int id, void *addr)`.
// `cmd = (subcmd << 8) | (qtype & 0xff)`. This file is ABI decode/usercopy
// only; quota state mutation lives in `vfs::quota`.
//
// Module manifest:
// - `179_quotactl/abi.rs`: classic quotactl UAPI structs and usercopy helpers.
// - `179_quotactl/cmd.rs`: classic/XFS quotactl command constants and classification.
// - `179_quotactl/dispatch.rs`: targeted/global quotactl dispatch shared with hosted tests.
// - `179_quotactl/qidns.rs`: user-namespace resolution of the `id` argument.
// - `179_quotactl/tests.rs`: direct syscall/context errno-order coverage.
// - `179_quotactl_xfs.rs`: XFS-compatible command ABI and dispatch.
#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::{errno::Errno, SyscallArgs};

#[path = "179_quotactl/abi.rs"] mod abi;
#[path = "179_quotactl/cmd.rs"] mod cmd;
#[path = "179_quotactl/dispatch.rs"] mod dispatch;
#[path = "179_quotactl/qidns.rs"] mod qidns;
#[path = "179_quotactl/sys.rs"] mod sys;
#[cfg(test)] #[path = "179_quotactl/tests.rs"] mod tests;
#[path = "179_quotactl_xfs.rs"] mod xfs;
pub use cmd::*;
pub use dispatch::{quotactl_dispatch, quotactl_dispatch_sb, quotactl_dispatch_sb_fd, quotactl_noquota_dispatch};

#[inline]
fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_quotactl(cmd, special, id, addr)` — slot 179. # C: O(path)+O(N_sb)+FS
pub fn sys_quotactl(args: &SyscallArgs) -> i64 {
    sys::sys_quotactl(args)
}
