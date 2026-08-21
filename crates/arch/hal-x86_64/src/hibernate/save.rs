// Hibernation continuation capture using the sole suspend CPU-state owner.

use crate::suspend::SavedCpuState;

use super::{validate_header, ArchHeader, PlanError, ARCH_HEADER_VERSION, PAGE_BYTES};

#[cfg(feature = "debug-hibernate")]
fn trace(boundary: &'static [u8]) {
    klog::write_raw(b"[hibernate] x86_continuation=");
    klog::write_raw(boundary);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
fn trace(_: &'static [u8]) {}

/// Capture CPU-global state and enter the image callback from resumable asm.
///
/// `image` runs only after the assembly has stored its exact continuation and
/// stack in `state`. Consequently an image produced inside that callback owns
/// the state needed by the cold restore entry. On successful cold restore,
/// control returns here with zero; an ordinary callback return is forwarded.
///
/// # SAFETY: CPL=0, interrupts disabled, one CPU online, all live task FP
/// ownership already flushed, and `state` has a stable image-mapped address.
/// `image` obeys the hibernation snapshot ordering and does not move `state`.
/// # C: O(image callback)
/// # Ctx: IRQ-off, single-CPU
pub unsafe fn capture_image_continuation(
    state: &mut SavedCpuState, image: extern "C" fn() -> u64,
) -> u64 {
    trace(b"save_begin");
    // SAFETY: fn contract supplies the privileged single-CPU save context.
    unsafe { crate::suspend::save_processor_state(state); }
    trace(b"save_end");
    trace(b"lowlevel_begin");
    // SAFETY: state now contains CPU-global state and remains stable across the callback.
    let result = unsafe { crate::suspend::suspend_lowlevel(state, image) };
    // The low-level continuation can restore only registers required to make
    // this Rust frame reachable. Descriptor tables, syscall/base MSRs, PAT,
    // and XCR0 have one canonical owner and must be repaired before any caller
    // resumes ordinary kernel work. This is required on both a cold restore
    // and the save-side callback-return path.
    // A nonzero callback result is necessarily the still-live save kernel, so
    // its logging state is valid. Zero may be the cold image continuation and
    // cannot touch klog until processor-global state has been repaired.
    if result != 0 { trace(b"lowlevel_end_original"); trace(b"restore_begin"); }
    // SAFETY: suspend_lowlevel returned on the saved stack with IRQs still off
    // and this exact record still exclusively owned by the caller.
    unsafe { crate::suspend::restore_processor_state(state); }
    if result == 0 { trace(b"lowlevel_end_restored"); }
    trace(b"restore_end");
    result
}

/// Create the persistent architecture header after continuation capture.
///
/// CR3's PCID/control bits are intentionally removed; the temporary entry
/// installs the physical image root under PCID zero and the saved continuation
/// later restores the complete CR3 from `state`.
/// # C: O(1)
pub fn header_from_captured_state(
    state: &SavedCpuState, restored_entry_va: u64, restored_entry_pa: u64,
    xsave_xcr0: u64, cpu_signature: u64, paging_levels: u64,
) -> Result<ArchHeader, PlanError> {
    let h = ArchHeader { version: ARCH_HEADER_VERSION,
        continuation_va: state.resume_rip,
        cpu_state_va: state as *const SavedCpuState as u64,
        restore_entry_va: restored_entry_va, restore_entry_pa: restored_entry_pa,
        image_cr3_pa: state.cr3 & !(PAGE_BYTES - 1), xsave_xcr0,
        cpu_signature, paging_levels };
    validate_header(&h)?;
    Ok(h)
}
