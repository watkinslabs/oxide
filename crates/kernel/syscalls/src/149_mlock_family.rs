// 149 mlock / 150 munlock / 151 mlockall / 152 munlockall (docs/53 §0).
// Linux VM_LOCKED policy and resident-page materialization.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;
// mlockall(2) flags (uapi asm-generic/mman.h).
const MCL_CURRENT: u64 = 1;
const MCL_FUTURE:  u64 = 2;
const MCL_ONFAULT: u64 = 4;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn current_mm() -> Result<alloc::sync::Arc<vmm::AddressSpace>, Errno> {
    let cur = sched::live::current().ok_or(Errno::Einval)?;
    // SAFETY: mm slot single-mutator per `13§5`; running task on this CPU.
    let mm = unsafe { cur.mm_ref() }.ok_or(Errno::Einval)?;
    Ok(mm.clone())
}

fn locked_range(addr: u64, len: u64) -> Result<Option<(hal::UserVirtAddr, usize)>, Errno> {
    if len == 0 { return Ok(None); }
    let start = addr & !(PAGE - 1);
    let end = match addr.checked_add(len).and_then(|e| e.checked_add(PAGE - 1)) {
        Some(e) => e & !(PAGE - 1),
        None    => return Err(Errno::Einval),
    };
    if end > hal::USER_VA_END || end < start { return Err(Errno::Enomem); }
    let start = hal::UserVirtAddr::new(start).ok_or(Errno::Enomem)?;
    Ok(Some((start, (end - start.as_u64()) as usize)))
}

fn validate_mapped(mm: &vmm::AddressSpace, start: hal::UserVirtAddr, len: usize) -> Result<(), Errno> {
    let mut va = start.as_u64();
    let end = va + len as u64;
    while va < end {
        let p = hal::UserVirtAddr::new(va).ok_or(Errno::Enomem)?;
        if mm.find_vma(p).is_none() { return Err(Errno::Enomem); }
        va += PAGE;
    }
    Ok(())
}

fn populate_locked_range(mm: &vmm::AddressSpace, start: hal::UserVirtAddr, len: usize) -> Result<(), Errno> {
    let end = start.as_u64().checked_add(len as u64).ok_or(Errno::Enomem)?;
    for vma in mm.snapshot_vmas() {
        let seg_start = core::cmp::max(start.as_u64(), vma.start.as_u64());
        let seg_end = core::cmp::min(end, vma.end.as_u64());
        if seg_start >= seg_end { continue; }
        let uva = hal::UserVirtAddr::new(seg_start).ok_or(Errno::Enomem)?;
        pmm::user_as::populate_current_range(uva, (seg_end - seg_start) as usize, vma.prot)
            .map_err(|_| Errno::Enomem)?;
    }
    Ok(())
}

/// Apply the PMM-side mlock transition to present LRU pages in a VMA range.
/// VMA policy remains VMM-owned; PageMeta LRU state remains PMM-owned. Pages
/// without reclaim ownership (page tables, device mappings, kernel bytes) are
/// intentionally ignored rather than assigned an invented class. # C: O(len/PAGE)
fn transition_resident_lru(start: hal::UserVirtAddr, len: usize, locked: bool) {
    use hal::{MmuOps, Va};
    let mut va = start.as_u64();
    let end = va.saturating_add(len as u64);
    while va < end {
        // mlock runs for the current task, whose active root is the same
        // address space `populate_current_range` just resolved.
        #[cfg(target_arch = "x86_64")]
        let present = hal_x86_64::mmu_ops::X86Mmu::translate(Va(va));
        #[cfg(target_arch = "aarch64")]
        let present = hal_aarch64::mmu_ops::ArmMmu::translate(Va(va));
        if let Some((pa, _)) = present {
            let _ = pmm::setup::set_lru_unevictable(pa.0 & !(PAGE - 1), locked);
        }
        va = va.saturating_add(PAGE);
    }
}

fn lock_current_mappings(mm: &vmm::AddressSpace, onfault: bool) -> Result<(), Errno> {
    for vma in mm.snapshot_vmas() {
        let len = (vma.end.as_u64() - vma.start.as_u64()) as usize;
        if !onfault { populate_locked_range(mm, vma.start, len)?; }
        mm.update_flags_range(vma.start, len, vmm::VmaFlags::LOCKED, vmm::VmaFlags::empty());
        if !onfault { transition_resident_lru(vma.start, len, true); }
    }
    Ok(())
}

/// Linux `can_do_mlock()` + `do_mlock()`'s RLIMIT_MEMLOCK ladder for the
/// running task. Split out so mlock(2) and mlock2(2) share ONE admission path:
/// an enforcement that lived only in mlock2 would let the same program lock the
/// same memory by picking the other slot. Decision logic is
/// `crate::mlock_policy` (hosted-tested); this reads the live task state.
/// # C: O(N_vmas)
fn memlock_admission(mm: &vmm::AddressSpace, start: hal::UserVirtAddr, len: usize) -> Result<(), Errno> {
    let cur = sched::live::current().ok_or(Errno::Einval)?;
    let has_ipc_lock = cur.has_cap(sched::cap::IPC_LOCK);
    let (limit, _max) = cur.rlimit(sched::rlimit::rlim::MEMLOCK);
    if !crate::mlock_policy::can_do_mlock(limit, has_ipc_lock) { return Err(Errno::Eperm); }
    let mm_locked = mm.accounting_snapshot().locked_virtual_bytes;
    let already = mm.locked_bytes_in_range(start, len);
    crate::mlock_policy::memlock_admits(len as u64, mm_locked, already, limit, has_ipc_lock)
}

/// Linux `do_mlock(start, len, flags)` — the body mlock(2) and mlock2(2) share.
/// `onfault` is mlock2's `MLOCK_ONFAULT` (Linux `VM_LOCKONFAULT`): the VMA is
/// marked locked but pages are NOT prefaulted, so they are pinned as they fault
/// in instead. # C: O(len/PAGE)
fn do_mlock(addr: u64, len_arg: u64, onfault: bool) -> i64 {
    let Some((start, len)) = (match locked_range(addr, len_arg) {
        Ok(v) => v,
        Err(e) => return err(e),
    }) else {
        return 0;
    };
    let mm = match current_mm() {
        Ok(m) => m, Err(e) => return err(e),
    };
    if let Err(e) = validate_mapped(&mm, start, len) { return err(e); }
    if let Err(e) = memlock_admission(&mm, start, len) { return err(e); }
    if !onfault {
        // Linux applies the VMA flags first and populates after dropping the
        // mmap lock; a populate failure is remapped by
        // `__mlock_posix_error_return` (EFAULT->ENOMEM, ENOMEM->EAGAIN).
        if let Err(e) = populate_locked_range(&mm, start, len) {
            return err(crate::mlock_policy::posix_error_return(e));
        }
    }
    mm.update_flags_range(start, len, vmm::VmaFlags::LOCKED, vmm::VmaFlags::empty());
    if !onfault { transition_resident_lru(start, len, true); }
    0
}

fn munlock_range(args: &SyscallArgs) -> i64 {
    let Some((start, len)) = (match locked_range(args.a0, args.a1) {
        Ok(v) => v,
        Err(e) => return err(e),
    }) else {
        return 0;
    };
    let mm = match current_mm() {
        Ok(m) => m, Err(e) => return err(e),
    };
    if let Err(e) = validate_mapped(&mm, start, len) { return err(e); }
    transition_resident_lru(start, len, false);
    mm.update_flags_range(start, len, vmm::VmaFlags::empty(), vmm::VmaFlags::LOCKED);
    0
}

/// `mlock(addr, len)` — slot 149. Linux `SYSCALL_DEFINE2(mlock)` =
/// `do_mlock(start, len, VM_LOCKED)`. # C: O(len/PAGE)
pub fn sys_mlock(args: &SyscallArgs) -> i64 { do_mlock(args.a0, args.a1, false) }

/// `mlock2(addr, len, flags)` — slot 325. Linux `SYSCALL_DEFINE3(mlock2)`:
/// reject any flag outside `MLOCK_ONFAULT`, then the same `do_mlock` mlock(2)
/// runs with `VM_LOCKONFAULT` added. The flag check precedes the EPERM/ENOMEM
/// ladder, so a bad flag reports EINVAL regardless of RLIMIT_MEMLOCK.
/// # C: O(len/PAGE)
pub fn sys_mlock2(args: &SyscallArgs) -> i64 {
    match crate::mlock_policy::mlock2_flags_check(args.a2) {
        Ok(onfault) => do_mlock(args.a0, args.a1, onfault),
        Err(e)      => err(e),
    }
}

/// `munlock(addr, len)` — slot 150. Validate mapped range, then clear VM_LOCKED.
/// # C: O(len/PAGE)
pub fn sys_munlock(args: &SyscallArgs) -> i64 { munlock_range(args) }

/// `mlockall(flags)` — slot 151. Locks current VMAs and/or persists the
/// policy to future mappings. `MCL_ONFAULT` is valid only with one of those
/// two actions, matching Linux. # C: O(current mapped pages)
pub fn sys_mlockall(args: &SyscallArgs) -> i64 {
    let flags = args.a0;
    let known = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;
    if flags == 0 || (flags & !known) != 0 || flags == MCL_ONFAULT { return err(Errno::Einval); }
    let mm = match current_mm() { Ok(mm) => mm, Err(e) => return err(e) };
    let onfault = (flags & MCL_ONFAULT) != 0;
    if (flags & MCL_CURRENT) != 0 {
        if let Err(e) = lock_current_mappings(&mm, onfault) { return err(e); }
    }
    if (flags & MCL_FUTURE) != 0 { mm.set_mlock_future(true, onfault); }
    0
}

/// `munlockall()` — slot 152. Clears current VM_LOCKED state and future
/// inheritance. # C: O(number of VMAs)
pub fn sys_munlockall(_args: &SyscallArgs) -> i64 {
    let mm = match current_mm() { Ok(mm) => mm, Err(e) => return err(e) };
    for vma in mm.snapshot_vmas() {
        let len = (vma.end.as_u64() - vma.start.as_u64()) as usize;
        transition_resident_lru(vma.start, len, false);
        mm.update_flags_range(vma.start, len, vmm::VmaFlags::empty(), vmm::VmaFlags::LOCKED);
    }
    mm.set_mlock_future(false, false);
    0
}
