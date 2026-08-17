//! CPU-local live exception-frame handoff.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use crate::PtRegs;

// A trap can sleep in the fault resolver while other CPUs take faults. The
// slot key must work before GS is live, because exceptions can arrive during
// per-CPU bring-up.
static LIVE: [AtomicPtr<PtRegs>; hal::MAX_SMP_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; hal::MAX_SMP_CPUS];
static LIVE_RSP: [AtomicU64; hal::MAX_SMP_CPUS] =
    [const { AtomicU64::new(0) }; hal::MAX_SMP_CPUS];
static LIVE_RIP: [AtomicU64; hal::MAX_SMP_CPUS] =
    [const { AtomicU64::new(0) }; hal::MAX_SMP_CPUS];

#[inline]
fn cpu_slot() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { super::fault_cpu() }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Publish this CPU's active exception frame and restore the prior nested
/// frame when the synchronous handler returns.
#[allow(dead_code)] // Referenced only by the x86 kernel exception entry.
pub(crate) fn publish(regs: *mut PtRegs) -> FrameGuard {
    // SAFETY: exception entry passed the live stub-built frame; this reads its
    // scalar user/kernel return state before exposing the pointer to consumers.
    let rsp = unsafe { (*regs).rsp };
    // SAFETY: same live entry-built frame as the `rsp` read above; `publish` has
    // not yet stored `regs` anywhere, so no other CPU can be mutating the frame.
    let rip = unsafe { (*regs).rip };
    publish_at(cpu_slot(), regs, rsp, rip)
}

#[allow(dead_code)] // Used by the kernel publisher and hosted nested-frame test.
fn publish_at(slot: usize, regs: *mut PtRegs, rsp: u64, rip: u64) -> FrameGuard {
    let prior = LIVE[slot].swap(regs, Ordering::AcqRel);
    let prior_rsp = LIVE_RSP[slot].swap(rsp, Ordering::AcqRel);
    let prior_rip = LIVE_RIP[slot].swap(rip, Ordering::AcqRel);
    FrameGuard { slot, prior, prior_rsp, prior_rip }
}

#[allow(dead_code)] // Its value keeps the live frame installed until trap return.
pub(crate) struct FrameGuard {
    slot: usize, prior: *mut PtRegs, prior_rsp: u64, prior_rip: u64,
}

impl Drop for FrameGuard {
    fn drop(&mut self) {
        LIVE_RSP[self.slot].store(self.prior_rsp, Ordering::Release);
        LIVE_RIP[self.slot].store(self.prior_rip, Ordering::Release);
        LIVE[self.slot].store(self.prior, Ordering::Release);
    }
}

/// The live `PtRegs` for this CPU's synchronous exception, if any.
///
/// Callers run in the exception path with preemption disabled at entry; nested
/// exceptions restore their predecessor through [`FrameGuard`].
pub fn current_fault_frame() -> *mut PtRegs {
    LIVE[cpu_slot()].load(Ordering::Acquire)
}

/// The saved RSP of this CPU's active exception frame, without dereferencing
/// the frame pointer after fault dispatch has handed control to another task.
/// # C: O(1)
pub fn current_fault_rsp() -> u64 {
    let slot = cpu_slot();
    if LIVE[slot].load(Ordering::Acquire).is_null() { return 0; }
    LIVE_RSP[slot].load(Ordering::Acquire)
}

/// The saved RIP of this CPU's active exception frame, without dereferencing
/// the frame pointer after fault dispatch may have switched tasks.
/// # C: O(1)
#[allow(dead_code)] // consumed by debug-faultdiag only in kernel feature builds
pub fn current_fault_rip() -> u64 {
    let slot = cpu_slot();
    if LIVE[slot].load(Ordering::Acquire).is_null() { return 0; }
    LIVE_RIP[slot].load(Ordering::Acquire)
}

/// Capture this CPU's active synchronous fault frame for the outgoing task.
/// # C: O(1)
pub fn capture_current_fault_frame() -> (u64, u64, u64) { capture_at(cpu_slot()) }

/// Restore the incoming task's active synchronous fault frame on this CPU.
/// # C: O(1)
pub fn restore_current_fault_frame(frame: u64, rsp: u64, rip: u64) {
    restore_at(cpu_slot(), frame, rsp, rip);
}

fn capture_at(slot: usize) -> (u64, u64, u64) {
    let frame = LIVE[slot].load(Ordering::Acquire);
    if frame.is_null() { return (0, 0, 0); }
    (frame as usize as u64, LIVE_RSP[slot].load(Ordering::Acquire), LIVE_RIP[slot].load(Ordering::Acquire))
}

fn restore_at(slot: usize, frame: u64, rsp: u64, rip: u64) {
    LIVE_RSP[slot].store(rsp, Ordering::Release);
    LIVE_RIP[slot].store(rip, Ordering::Release);
    LIVE[slot].store(frame as usize as *mut PtRegs, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_slots_never_cross_publish_live_frames() {
        let a = 0x1000usize as *mut PtRegs;
        let b = 0x2000usize as *mut PtRegs;
        LIVE[1].store(a, Ordering::Release);
        LIVE[2].store(b, Ordering::Release);
        assert_eq!(LIVE[1].load(Ordering::Acquire), a);
        assert_eq!(LIVE[2].load(Ordering::Acquire), b);
        LIVE[1].store(core::ptr::null_mut(), Ordering::Release);
        LIVE[2].store(core::ptr::null_mut(), Ordering::Release);
    }

    #[test]
    fn nested_fault_restores_its_predecessor() {
        let slot = 3;
        let outer = 0x3000usize as *mut PtRegs;
        let inner = 0x4000usize as *mut PtRegs;
        let outer_guard = publish_at(slot, outer, 0x3000, 0x3001);
        {
            let inner_guard = publish_at(slot, inner, 0x4000, 0x4001);
            assert_eq!(LIVE[slot].load(Ordering::Acquire), inner);
            assert_eq!(LIVE_RSP[slot].load(Ordering::Acquire), 0x4000);
            assert_eq!(LIVE_RIP[slot].load(Ordering::Acquire), 0x4001);
            drop(inner_guard);
        }
        assert_eq!(LIVE[slot].load(Ordering::Acquire), outer);
        assert_eq!(LIVE_RSP[slot].load(Ordering::Acquire), 0x3000);
        assert_eq!(LIVE_RIP[slot].load(Ordering::Acquire), 0x3001);
        drop(outer_guard);
        assert!(LIVE[slot].load(Ordering::Acquire).is_null());
        assert_eq!(LIVE_RSP[slot].load(Ordering::Acquire), 0);
        assert_eq!(LIVE_RIP[slot].load(Ordering::Acquire), 0);
        LIVE[slot].store(core::ptr::null_mut(), Ordering::Release);
    }

    #[test]
    fn scalar_rsp_is_available_without_dereferencing_the_frame_pointer() {
        let slot = cpu_slot();
        let frame = 0x5000usize as *mut PtRegs;
        let guard = publish_at(slot, frame, 0xfeed_1000, 0xfeed_2000);
        assert_eq!(current_fault_rsp(), 0xfeed_1000);
        assert_eq!(current_fault_rip(), 0xfeed_2000);
        drop(guard);
        assert_eq!(current_fault_rsp(), 0);
        assert_eq!(current_fault_rip(), 0);
    }

    #[test]
    fn page_fault_entry_snapshots_cr2_before_interrupt_enable() {
        let asm = include_str!("stubs.rs");
        let capture = asm.find("call oxide_fault_capture_cr2").unwrap();
        let forward = capture + asm[capture..].find("mov  rsi, rax").unwrap();
        let sti = forward + asm[forward..].find("    sti").unwrap();
        let dispatch = sti + asm[sti..].find("call oxide_fault_print_rust").unwrap();
        assert!(capture < forward && forward < sti && sti < dispatch);
    }

    #[test]
    fn task_handoff_restores_the_fault_frame_and_scalars_together() {
        const SLOT: usize = 4;
        let a = 0x6000usize as *mut PtRegs;
        let b = 0x7000usize as *mut PtRegs;
        let a_guard = publish_at(SLOT, a, 0xa000, 0xa001);
        let a_state = capture_at(SLOT);
        restore_at(SLOT, 0, 0, 0);
        let b_guard = publish_at(SLOT, b, 0xb000, 0xb001);
        let b_state = capture_at(SLOT);
        restore_at(SLOT, a_state.0, a_state.1, a_state.2);
        assert_eq!(capture_at(SLOT), a_state);
        restore_at(SLOT, b_state.0, b_state.1, b_state.2);
        assert_eq!(capture_at(SLOT), b_state);
        drop(b_guard);
        drop(a_guard);
        restore_at(SLOT, 0, 0, 0);
    }
}
