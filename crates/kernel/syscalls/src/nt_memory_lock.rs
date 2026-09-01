//! Native Windows virtual-memory locking over the VMM mlock owner.

#![cfg(target_os = "oxide-kernel")]

use syscall::UserPtr;
use vmm::{AddressSpace, LockedSpan, VmaFlags};

const PAGE: u64 = hal::PAGE_SIZE_BYTES;
const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;

/// Implement the current-process half of Wine's `NtLockVirtualMemory`.
/// Wine rounds the user range, publishes that rounded range, then calls the
/// host lock primitive. VMM owns the durable lock flag; this adapter owns
/// population and PMM unevictable state for pages made resident by the call.
pub fn dispatch(mm: &AddressSpace, address: UserPtr<u64>, size: UserPtr<u64>) -> u64 {
    let raw_address = match uaccess::get_user_u64(address.as_u64()) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    let raw_size = match uaccess::get_user_u64(size.as_u64()) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    let start = raw_address & !(PAGE - 1);
    let Some(end) = raw_address.checked_add(raw_size).and_then(|value| value.checked_add(PAGE - 1))
        .map(|value| value & !(PAGE - 1)) else { return STATUS_INVALID_PARAMETER };
    let Some(length) = end.checked_sub(start) else { return STATUS_INVALID_PARAMETER };
    if uaccess::put_user_u64(address.as_u64(), start).is_err()
        || uaccess::put_user_u64(size.as_u64(), length).is_err() { return STATUS_INVALID_PARAMETER; }
    let Some(start) = hal::UserVirtAddr::new(start) else { return STATUS_ACCESS_DENIED };
    let Ok(length) = usize::try_from(length) else { return STATUS_ACCESS_DENIED };
    let outcome = mm.apply_vma_lock_flags(start, length, VmaFlags::LOCKED);
    if outcome.error.is_some() { return STATUS_ACCESS_DENIED; }
    if populate(mm, &outcome.spans).is_err() { return STATUS_ACCESS_DENIED; }
    STATUS_SUCCESS
}

fn populate(mm: &AddressSpace, spans: &[LockedSpan]) -> Result<(), ()> {
    for span in spans {
        let end = span.start.as_u64().checked_add(span.len as u64).ok_or(())?;
        for vma in mm.snapshot_vmas() {
            let start = core::cmp::max(span.start.as_u64(), vma.start.as_u64());
            let end = core::cmp::min(end, vma.end.as_u64());
            if start >= end { continue; }
            let address = hal::UserVirtAddr::new(start).ok_or(())?;
            pmm::user_as::populate_current_range(address, (end - start) as usize, vma.prot).map_err(|_| ())?;
        }
        mark_unevictable(span);
    }
    Ok(())
}

fn mark_unevictable(span: &LockedSpan) {
    use hal::{MmuOps, Va};
    let mut address = span.start.as_u64();
    let end = address.saturating_add(span.len as u64);
    while address < end {
        #[cfg(target_arch = "x86_64")]
        let present = hal_x86_64::mmu_ops::X86Mmu::translate(Va(address));
        #[cfg(target_arch = "aarch64")]
        let present = hal_aarch64::mmu_ops::ArmMmu::translate(Va(address));
        if let Some((physical, _)) = present {
            let _ = pmm::setup::set_lru_unevictable(physical.0 & !(PAGE - 1), true);
        }
        address = address.saturating_add(PAGE);
    }
}
