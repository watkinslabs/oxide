// 238 set_mempolicy — `SYSCALL_DEFINE3(set_mempolicy)` / `kernel_set_mempolicy`
// (`mm/mempolicy.c:1835`). ABI shim (docs/53): the ladder is
// `vmm::mempolicy::{sanitize_mpol_flags, mpol_new}`, the storage is
// `Task::set_mempolicy`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use vmm::mempolicy::{mpol_new, sanitize_mpol_flags};

use crate::misc::mempolicy_common::{errno_of, read_nodemask};

/// `set_mempolicy(mode, nmask, maxnode)`.
///
/// Order is load-bearing: `sanitize_mpol_flags` runs BEFORE the nodemask is
/// fetched, so an illegal mode outranks an unreadable `nmask`.
/// # C: O(maxnode / 64)
pub fn sys_set_mempolicy(args: &SyscallArgs) -> i64 {
    // Linux declares `int mode`; only the low 32 bits reach the handler.
    let (mode_arg, nmask, maxnode) = (args.a0 as u32, args.a1, args.a2);
    let (mode, flags) = match sanitize_mpol_flags(mode_arg) {
        Ok(v) => v, Err(e) => return errno_of(e),
    };
    let nodes = match read_nodemask(nmask, maxnode) { Ok(n) => n, Err(rv) => return rv };
    let pol = match mpol_new(mode, flags, nodes) { Ok(p) => p, Err(e) => return errno_of(e) };
    let Some(cur) = sched::live::current() else { return errno_of(vmm::Error::Inval) };
    cur.set_mempolicy(pol);
    0
}
