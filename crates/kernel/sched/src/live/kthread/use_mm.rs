// Borrowing a user address space on a kernel thread.
//
// A kernel thread that has to write through USER addresses — loading a program
// image into a process it is building — must install that address space as its
// own, not merely switch the page-table root. The root register alone is not
// enough: the moment the thread sleeps (an image read hits the disk), the
// scheduler restores the root of whichever task ran next and does NOT restore
// the borrowed one on the way back, because a thread with no address space is
// treated as lazily resident on whatever is already installed. The thread then
// resumes writing user addresses through SOMEBODY ELSE'S page tables.
//
// Installing the space is what makes the scheduler's restore correct, since it
// then sees a real address space on the way in and out.

use alloc::sync::Arc;

use hal::MmuOps;
use vmm::AddressSpace;

#[cfg(target_arch = "x86_64")]
type ActiveMmu = hal_x86_64::mmu_ops::X86Mmu;
#[cfg(target_arch = "aarch64")]
type ActiveMmu = hal_aarch64::mmu_ops::ArmMmu;

/// Borrow `mm` on the running kernel thread and install its page-table root.
///
/// # SAFETY: the running task must be a kernel thread with no address space of
/// its own, so nothing is displaced; `mm`'s root must carry the shared kernel
/// half. Every borrow must be released with [`kthread_unuse_mm`] before the
/// thread does anything else with user addresses.
/// # C: O(1)
/// # Ctx: process
pub unsafe fn kthread_use_mm(mm: &Arc<AddressSpace>) {
    let Some(cur) = super::super::schedule::current() else { return };
    let me = super::super::schedule::sched_current_cpu();
    // The shootdown sender consults this mask, so it is set BEFORE the root is
    // installed: an unmap on another processor between the two would otherwise
    // skip this one and leave it running on a stale translation.
    mm.mark_cpu(me);
    // SAFETY: forwarded fn-level contract — the running task is a kernel thread with no address space, so this replace displaces nothing.
    unsafe { cur.replace_borrowed_mm(Some(Arc::clone(mm))); }
    // SAFETY: forwarded fn-level contract — the root carries the shared kernel half, so kernel mappings stay valid across the write.
    unsafe { ActiveMmu::activate(mm.root_pa()); }
}

/// Release the borrow. The root STAYS installed — this processor is now lazily
/// resident on it, exactly as it would be after switching from a user task to a
/// kernel thread — and the released space is pinned until the next real
/// activation, so it cannot be freed while still installed.
/// # SAFETY: must pair with a preceding [`kthread_use_mm`] on the same thread.
/// # C: O(1)
/// # Ctx: process
pub unsafe fn kthread_unuse_mm() {
    let Some(cur) = super::super::schedule::current() else { return };
    // SAFETY: forwarded fn-level contract — the borrow installed here is the only address space this kernel thread has, and `replace_mm` parks it so the root survives while still installed.
    unsafe { cur.replace_borrowed_mm(None); }
}
