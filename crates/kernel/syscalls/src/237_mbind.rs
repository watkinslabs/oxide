// 237 mbind — `SYSCALL_DEFINE6(mbind)` / `kernel_mbind` (`mm/mempolicy.c:1827`)
// + `do_mbind` (`:1486`). ABI shim (docs/53): validation lives in
// `vmm::mempolicy::{sanitize_mpol_flags, mpol_new, args, scan}`, the VMA
// rewrite in `AddressSpace::set_policy_range`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use vmm::mempolicy::args::{align_range, mbind_flags};
use vmm::mempolicy::scan::{MPOL_MF_DISCONTIG_OK, MPOL_MF_INVERT};
use vmm::mempolicy::uapi::{MPOL_DEFAULT, MPOL_MF_STRICT};
use vmm::mempolicy::{mpol_new, queue_pages_range, sanitize_mpol_flags};

use crate::misc::mempolicy_common::{cap_sys_nice, current_mm, err, errno_of, page_present,
    read_nodemask};

/// `mbind(start, len, mode, nmask, maxnode, flags)`.
///
/// Errno order, verbatim: bad mode (EINVAL) → unreadable nmask (EFAULT) →
/// bad mbind flag (EINVAL) → MPOL_MF_MOVE_ALL without CAP_SYS_NICE (EPERM) →
/// unaligned start / wrapped end (EINVAL) → illegal mode+nodemask pairing
/// (EINVAL) → hole in range (EFAULT) → MPOL_MF_STRICT violation (EIO).
/// # C: O(N_pages + K log N)
pub fn sys_mbind(args: &SyscallArgs) -> i64 {
    let (start, len, mode_arg) = (args.a0, args.a1, args.a2 as u32);
    let (nmask, maxnode, mut flags) = (args.a3, args.a4, args.a5 & 0xffff_ffff);
    let (mode, mode_flags) = match sanitize_mpol_flags(mode_arg) {
        Ok(v) => v, Err(e) => return errno_of(e),
    };
    let nodes = match read_nodemask(nmask, maxnode) { Ok(n) => n, Err(rv) => return rv };
    if let Err(e) = mbind_flags(flags, cap_sys_nice()) { return errno_of(e); }
    // `if (mode == MPOL_DEFAULT) flags &= ~MPOL_MF_STRICT` — a default policy
    // makes no placement claim, so nothing can violate it.
    if mode == MPOL_DEFAULT { flags &= !MPOL_MF_STRICT; }
    let range = match align_range(start, len) { Ok(r) => r, Err(e) => return errno_of(e) };
    // `mpol_new` runs even for a zero-length range in Linux? No: the
    // `end == start` return is BEFORE mpol_new (`mm/mempolicy.c:1510`), so an
    // illegal mode+nodemask pairing over a zero-length range still returns 0.
    let Some((start, end)) = range else { return 0 };
    let pol = match mpol_new(mode, mode_flags, nodes) { Ok(p) => p, Err(e) => return errno_of(e) };
    // A NULL policy (MPOL_DEFAULT) sets MPOL_MF_DISCONTIG_OK: operating on
    // discontiguous address space is fine when no policy is installed.
    let scan_flags = flags | MPOL_MF_INVERT
        | if pol.is_none() { MPOL_MF_DISCONTIG_OK } else { 0 };
    let Some(mm) = current_mm() else { return errno_of(vmm::Error::Inval) };
    let vmas = mm.snapshot_vmas();
    // `queue_pages_range` walks with the RAW user nodemask, not the effective
    // one — that is what makes mbind(MPOL_LOCAL, MPOL_MF_STRICT) reportable.
    let nr_failed = match queue_pages_range(&vmas, start, end, nodes, scan_flags, page_present) {
        Ok(n) => n, Err(e) => return errno_of(e),
    };
    mm.set_policy_range(start, end, pol);
    if nr_failed != 0 && flags & MPOL_MF_STRICT != 0 { return err(syscall::errno::Errno::Eio); }
    0
}
