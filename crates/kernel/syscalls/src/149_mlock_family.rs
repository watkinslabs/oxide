// 149 mlock / 150 munlock / 151 mlockall / 152 munlockall (docs/53 §0).
// No swap → a locked page is trivially resident; the residency guarantee is
// met by construction. But Linux still VALIDATES: mlock/munlock return ENOMEM
// when the range spans unmapped addresses, and mlockall rejects bad MCL_* flags.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

const PAGE: u64 = 0x1000;
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

fn mlock_range(args: &SyscallArgs, set_locked: bool) -> i64 {
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
    if set_locked {
        mm.update_flags_range(start, len, vmm::VmaFlags::LOCKED, vmm::VmaFlags::empty());
    } else {
        mm.update_flags_range(start, len, vmm::VmaFlags::empty(), vmm::VmaFlags::LOCKED);
    }
    0
}

/// `mlock(addr, len)` — slot 149. Validate mapped range, then set VM_LOCKED.
/// # C: O(len/PAGE)
pub fn sys_mlock(args: &SyscallArgs) -> i64 { mlock_range(args, true) }

/// `munlock(addr, len)` — slot 150. Validate mapped range, then clear VM_LOCKED.
/// # C: O(len/PAGE)
pub fn sys_munlock(args: &SyscallArgs) -> i64 { mlock_range(args, false) }

/// `mlockall(flags)` — slot 151. Reject flags==0 or unknown bits (Linux
/// EINVAL); otherwise a no-op success (every page is resident, no swap).
/// # C: O(1)
pub fn sys_mlockall(args: &SyscallArgs) -> i64 {
    let flags = args.a0;
    let known = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;
    if flags == 0 || (flags & !known) != 0 { return err(Errno::Einval); }
    0
}

/// `munlockall()` — slot 152. Always succeeds. # C: O(1)
pub fn sys_munlockall(_args: &SyscallArgs) -> i64 { 0 }
