// 149 mlock / 150 munlock / 151 mlockall / 152 munlockall / 325 mlock2
// (docs/53 §0). ABI shim only: round arguments (`crate::mlock_policy`), run the
// RLIMIT_MEMLOCK ladder, hand the VMA transition to the VMM
// (`AddressSpace::apply_vma_lock_flags` / `apply_mlockall_flags`), then
// prefault and pin what came back.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vmm::{LockedSpan, VmaFlags};

use crate::mlock_policy as policy;

const PAGE: u64 = hal::PAGE_SIZE_BYTES;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn current_mm() -> Result<alloc::sync::Arc<vmm::AddressSpace>, Errno> {
    let cur = sched::live::current().ok_or(Errno::Einval)?;
    // SAFETY: mm slot single-mutator per `13§5`; running task on this CPU.
    let mm = unsafe { cur.mm_ref() }.ok_or(Errno::Einval)?;
    Ok(mm.clone())
}

/// Map a VMM VMA-walk failure onto the mlock errno domain.
/// # C: O(1)
fn walk_errno(e: vmm::Error) -> Errno {
    match e { vmm::Error::Inval => Errno::Einval, _ => Errno::Enomem }
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

/// Linux `__mm_populate` over the spans an mlock transition actually locked.
/// `MLOCK_ONFAULT` spans are skipped: their pages are pinned as they fault in,
/// which is the entire point of the flag. Every populated span then has its
/// resident pages moved to the unevictable LRU.
/// # C: O(sum(len)/PAGE)
fn populate_spans(mm: &vmm::AddressSpace, spans: &[LockedSpan]) -> Result<(), Errno> {
    for span in spans {
        if span.onfault { continue; }
        let end = span.start.as_u64().saturating_add(span.len as u64);
        for vma in mm.snapshot_vmas() {
            let s = core::cmp::max(span.start.as_u64(), vma.start.as_u64());
            let e = core::cmp::min(end, vma.end.as_u64());
            if s >= e { continue; }
            let uva = hal::UserVirtAddr::new(s).ok_or(Errno::Enomem)?;
            pmm::user_as::populate_current_range(uva, (e - s) as usize, vma.prot)
                .map_err(|_| Errno::Enomem)?;
        }
        transition_resident_lru(span.start, span.len, true);
    }
    Ok(())
}

/// Linux `can_do_mlock()` + `do_mlock()`'s RLIMIT_MEMLOCK ladder for the
/// running task. Split out so mlock(2) and mlock2(2) share ONE admission path:
/// an enforcement that lived only in mlock2 would let the same program lock the
/// same memory by picking the other slot. Decision logic is
/// `crate::mlock_policy` (hosted-tested); this reads the live task state.
/// # C: O(N_vmas)
fn memlock_admission(mm: &vmm::AddressSpace, start: hal::UserVirtAddr, len: usize)
    -> Result<(), Errno>
{
    let cur = sched::live::current().ok_or(Errno::Einval)?;
    let has_ipc_lock = cur.has_cap(sched::cap::IPC_LOCK);
    let (limit, _max) = cur.rlimit(sched::rlimit::rlim::MEMLOCK);
    let mm_locked = mm.accounting_snapshot().locked_virtual_bytes;
    let already = mm.locked_bytes_in_range(start, len);
    policy::memlock_admits(len as u64, mm_locked, already, limit, has_ipc_lock)
}

/// Whether the running task may lock any memory at all — Linux `can_do_mlock`,
/// which `do_mlock` and `mlockall` both evaluate BEFORE looking at their
/// arguments, so an EPERM answer is not disturbed by a malformed range.
/// # C: O(1)
fn can_do_mlock() -> Result<(), Errno> {
    let cur = sched::live::current().ok_or(Errno::Einval)?;
    let (limit, _max) = cur.rlimit(sched::rlimit::rlim::MEMLOCK);
    if policy::can_do_mlock(limit, cur.has_cap(sched::cap::IPC_LOCK)) { Ok(()) }
    else { Err(Errno::Eperm) }
}

/// Linux `do_mlock(start, len, flags)` — the body mlock(2) and mlock2(2) share.
/// Ordering is Linux's and is observable: EPERM (may not lock at all) precedes
/// the argument rounding, which precedes the RLIMIT_MEMLOCK ENOMEM, which
/// precedes the VMA walk. The walk applies flags VMA by VMA and does NOT undo
/// them when it meets a hole, so a range with a gap in the middle reports
/// ENOMEM with everything before the gap left locked.
/// # C: O(len/PAGE)
fn do_mlock(addr: u64, len_arg: u64, onfault: bool) -> i64 {
    if let Err(e) = can_do_mlock() { return err(e); }
    let (start, len) = match policy::mlock_range(addr, len_arg, PAGE) {
        Ok(Some(r)) => r,
        Ok(None)    => return 0,
        Err(e)      => return err(e),
    };
    let Some(start) = hal::UserVirtAddr::new(start) else { return err(Errno::Enomem) };
    let mm = match current_mm() { Ok(m) => m, Err(e) => return err(e) };
    if let Err(e) = memlock_admission(&mm, start, len as usize) { return err(e); }
    let add = if onfault { VmaFlags::LOCKED_MASK } else { VmaFlags::LOCKED };
    let out = mm.apply_vma_lock_flags(start, len as usize, add);
    if let Some(e) = out.error { return err(walk_errno(e)); }
    // Linux populates after dropping the mmap lock and remaps the failure
    // through `__mlock_posix_error_return` (EFAULT->ENOMEM, ENOMEM->EAGAIN).
    if let Err(e) = populate_spans(&mm, &out.spans) { return err(policy::posix_error_return(e)); }
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
    match policy::mlock2_flags_check(args.a2) {
        Ok(onfault) => do_mlock(args.a0, args.a1, onfault),
        Err(e)      => err(e),
    }
}

/// `munlock(addr, len)` — slot 150. Linux `SYSCALL_DEFINE2(munlock)` rounds the
/// same way mlock does and then clears `VM_LOCKED_MASK`; it runs NO capability
/// or RLIMIT_MEMLOCK check, because giving memory back is never denied.
/// # C: O(len/PAGE)
pub fn sys_munlock(args: &SyscallArgs) -> i64 {
    let (start, len) = match policy::mlock_range(args.a0, args.a1, PAGE) {
        Ok(Some(r)) => r,
        Ok(None)    => return 0,
        Err(e)      => return err(e),
    };
    let Some(start) = hal::UserVirtAddr::new(start) else { return err(Errno::Enomem) };
    let mm = match current_mm() { Ok(m) => m, Err(e) => return err(e) };
    transition_resident_lru(start, len as usize, false);
    let out = mm.apply_vma_lock_flags(start, len as usize, VmaFlags::empty());
    match out.error { Some(e) => err(walk_errno(e)), None => 0 }
}

/// `mlockall(flags)` — slot 151. Flags first (EINVAL), then `can_do_mlock`
/// (EPERM), then the whole-address-space RLIMIT_MEMLOCK charge that only
/// `MCL_CURRENT` incurs (ENOMEM). `MCL_FUTURE` writes `mm->def_flags`, which
/// later mmap(2)s inherit; the write is unconditional, so an `mlockall` WITHOUT
/// `MCL_FUTURE` clears a policy an earlier call installed. Population failures
/// are ignored, matching Linux's unchecked `mm_populate` tail.
/// # C: O(current mapped pages)
pub fn sys_mlockall(args: &SyscallArgs) -> i64 {
    let (current, future, onfault) = match policy::mlockall_flags_check(args.a0) {
        Ok(v) => v, Err(e) => return err(e),
    };
    let mm = match current_mm() { Ok(mm) => mm, Err(e) => return err(e) };
    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Einval) };
    let has_ipc_lock = cur.has_cap(sched::cap::IPC_LOCK);
    let (limit, _max) = cur.rlimit(sched::rlimit::rlim::MEMLOCK);
    if let Err(e) = policy::mlockall_admits(current, mm.total_mapped_bytes(), limit, has_ipc_lock) {
        return err(e);
    }
    let spans = mm.apply_mlockall_flags(future, current, onfault);
    let _ = populate_spans(&mm, &spans);
    0
}

/// `munlockall()` — slot 152. Linux `apply_mlockall_flags(0)`: drop the
/// `MCL_FUTURE` policy from `mm->def_flags` AND clear `VM_LOCKED_MASK` from
/// every VMA, including the `VM_LOCKONFAULT` half. # C: O(number of VMAs)
pub fn sys_munlockall(_args: &SyscallArgs) -> i64 {
    let mm = match current_mm() { Ok(mm) => mm, Err(e) => return err(e) };
    for span in mm.munlock_all() { transition_resident_lru(span.start, span.len, false); }
    0
}
