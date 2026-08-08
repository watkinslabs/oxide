// Shared kernel-side glue for the mempolicy slots (237/238/239/256/279/450):
// errno mapping, nodemask usercopy, and the current-task/mm fetches.
//
// Decision logic deliberately lives in `vmm::mempolicy`, which is NOT
// target-gated and therefore hosted-testable; this file is the usercopy that
// cannot be.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;
use vmm::mempolicy::nodemask::NodeMask;
use vmm::mempolicy::{copy_nodes_to_user_plan, get_nodes};
use vmm::AddressSpace;

/// `Error` (`docs/38`) → the negative errno a syscall returns. # C: O(1)
pub(crate) fn errno_of(e: vmm::Error) -> i64 {
    let n = match e {
        vmm::Error::Inval => Errno::Einval,
        vmm::Error::Fault => Errno::Efault,
        vmm::Error::Perm => Errno::Eperm,
        vmm::Error::NoMem => Errno::Enomem,
        vmm::Error::Access => Errno::Eacces,
        vmm::Error::Io => Errno::Eio,
        vmm::Error::Again => Errno::Eagain,
        vmm::Error::NotImplemented => Errno::Einval,
    };
    -(n.as_i32() as i64)
}

/// Negative-errno encoding for a syscall return. # C: O(1)
#[inline]
pub(crate) fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The running task's address space. # C: O(1)
pub(crate) fn current_mm() -> Option<Arc<AddressSpace>> {
    let cur = sched::live::current()?;
    // SAFETY: mm slot is single-mutator per `13§5`; we are the running task on
    // this CPU and the sole reader for the duration of the syscall.
    unsafe { cur.mm_ref() }.map(|m| m.clone())
}

/// `get_nodes(nodes, nmask, maxnode)` with the real usercopy: each
/// `unsigned long` of the caller's bitmap is fetched as 8 bytes, and a word
/// the caller did not map is EFAULT — not a silently-zero nodemask.
/// # C: O(maxnode / 64)
pub(crate) fn read_nodemask(nmask: u64, maxnode: u64) -> Result<NodeMask, i64> {
    get_nodes(nmask != 0, maxnode, |i| {
        let off = i.checked_mul(8).ok_or(vmm::Error::Fault)?;
        let at = nmask.checked_add(off).ok_or(vmm::Error::Fault)?;
        let mut buf = [0u8; 8];
        uaccess::copy_from_user(&mut buf, at).map_err(|_| vmm::Error::Fault)?;
        Ok(u64::from_ne_bytes(buf))
    }).map_err(errno_of)
}

/// `copy_nodes_to_user(mask, maxnode, nodes)`: copy the real mask, then
/// zero-fill whatever extra width the caller asked for. libnuma always asks
/// for `MAX_NUMNODES` worth, so the zero-fill leg is the common one.
/// # C: O(maxnode / 8)
pub(crate) fn write_nodemask(nmask: u64, maxnode: u64, nodes: NodeMask) -> Result<(), i64> {
    let plan = copy_nodes_to_user_plan(maxnode).map_err(errno_of)?;
    if plan.copy_bytes > 0 {
        let raw = nodes.0.to_ne_bytes();
        uaccess::copy_to_user(nmask, &raw[..plan.copy_bytes as usize])
            .map_err(|_| err(Errno::Efault))?;
    }
    let mut done = 0u64;
    while done < plan.clear_bytes {
        let chunk = core::cmp::min(plan.clear_bytes - done, 64) as usize;
        let zeros = [0u8; 64];
        let at = nmask.checked_add(plan.clear_off + done).ok_or(err(Errno::Efault))?;
        uaccess::copy_to_user(at, &zeros[..chunk]).map_err(|_| err(Errno::Efault))?;
        done += chunk as u64;
    }
    Ok(())
}

/// `capable(CAP_SYS_NICE)` for the running task. # C: O(1)
pub(crate) fn cap_sys_nice() -> bool {
    sched::live::current().is_some_and(|c| c.has_cap(sched::cap::SYS_NICE))
}

/// `page_present(va)` — the PTE query `queue_pages_range` and
/// `folio_walk_start` need. # C: O(walk depth)
pub(crate) fn page_present(va: u64) -> bool {
    use hal::{MmuOps, Va};
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::X86Mmu::translate(Va(va)).is_some() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::ArmMmu::translate(Va(va)).is_some() }
}

/// `page_present(va)` in a possibly-FOREIGN address space — `move_pages(pid)`
/// walks the target's tables, not the caller's. # C: O(walk depth)
pub(crate) fn page_present_in(mm: &AddressSpace, va: u64) -> bool {
    let hhdm = pmm::user_as::hhdm_offset();
    // SAFETY: `mm` is pinned by the caller's Arc for the duration of this
    // walk, its root_pa is a live top-level table, and HHDM covers page-table
    // memory; the walk is read-only and takes no lock the caller holds.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        { hal::pt_walker::translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(
            mm.root_pa(), va, hhdm).is_some() }
        #[cfg(target_arch = "aarch64")]
        { hal::pt_walker::translate_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(
            mm.root_pa(), va, hhdm).is_some() }
    }
}

/// `find_mm_struct`: pid 0 is the caller, otherwise the
/// target must exist (ESRCH) and pass `ptrace_may_access` (EPERM).
/// # C: O(N_tasks)
pub(crate) fn find_mm_struct(pid: u32) -> Result<Arc<AddressSpace>, i64> {
    if pid == 0 { return current_mm().ok_or(err(Errno::Einval)); }
    let cur = sched::live::current().ok_or(err(Errno::Esrch))?;
    let target = sched::live::registry::resolve_user_pid(pid).ok_or(err(Errno::Esrch))?;
    crate::s101_ptrace_perm::may_access(&cur, &target).map_err(|_| err(Errno::Eperm))?;
    target.clone_mm().ok_or(err(Errno::Einval))
}
