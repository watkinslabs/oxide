use core::sync::atomic::Ordering;

use super::ipi::{build_icr_lo, wait_icr_idle, write_icr};
use super::regs::{
    rdmsr, select_eoi_path, wrmsr, APIC_GLOBAL_ENABLE, LAPIC_BASE_VA, MSR_IA32_APIC_BASE, REG_ID,
    REG_SVR, REG_VERSION, SPURIOUS_VECTOR, SVR_ENABLE,
};

/// Outcome reported by `enable`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LapicStatus {
    /// `enable` already ran.
    AlreadyOn,
    /// LAPIC mapped + software-enabled. Returns (apic_id, version).
    Enabled { apic_id: u32, version: u32 },
}

/// Map LAPIC at `va` (covering `pa`) and software-enable it via SVR.
///
/// # SAFETY: caller asserts `va` is freshly mapped Device-attr over
/// the LAPIC page; runs single-CPU, IRQ-off; no other path is
/// touching the LAPIC. Caller is responsible for the device-mapping
/// step itself (use `hal_x86_64::vmm::map_device_4k`).
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn enable(va: u64) -> LapicStatus {
    if LAPIC_BASE_VA.load(Ordering::Acquire) != 0 {
        return LapicStatus::AlreadyOn;
    }
    // Make sure IA32_APIC_BASE.E is set (firmware usually leaves it on, but
    // be defensive -- bit 11 is the global enable).
    // SAFETY: rdmsr/wrmsr on IA32_APIC_BASE are privileged but
    // legal at CPL=0; bit 11 is the well-defined global-enable bit.
    unsafe {
        let cur = rdmsr(MSR_IA32_APIC_BASE);
        if (cur & APIC_GLOBAL_ENABLE) == 0 {
            wrmsr(MSR_IA32_APIC_BASE, cur | APIC_GLOBAL_ENABLE);
        }
    }
    // GAP-2 hardening: pick the EOI path (MSR if already in x2APIC mode).
    select_eoi_path();
    // Software-enable via SVR + park spurious-int on vector 0xFF.
    // SAFETY: `va` is the freshly-mapped Device-attr LAPIC page per fn contract; reads/writes lie within its 4 KiB.
    unsafe {
        let svr_addr = (va + REG_SVR as u64) as *mut u32;
        let cur = core::ptr::read_volatile(svr_addr);
        let new = (cur & !0xFF) | SPURIOUS_VECTOR | SVR_ENABLE;
        core::ptr::write_volatile(svr_addr, new);
    }
    // SAFETY: same contract; offset 0x20 + 0x30 within mapped page.
    let (apic_id, version) = unsafe {
        let id = core::ptr::read_volatile((va + REG_ID as u64) as *const u32);
        let ver = core::ptr::read_volatile((va + REG_VERSION as u64) as *const u32);
        // APIC ID is in bits 31:24 on the x2APIC-aware variants;
        // pre-Pentium-4 used bits 31:24 too. Shift down for log.
        (id >> 24, ver)
    };
    LAPIC_BASE_VA.store(va, Ordering::Release);
    LapicStatus::Enabled { apic_id, version }
}

/// Send a resched IPI to logical CPU `target_cpu`. The target is translated
/// through cpu_topology to the LAPIC APIC id before writing the ICR. The receiver
/// vectors through `oxide_irq_vec_41`, sets need_resched, and the
/// IRQ-exit picker switches if eligible. Returns false if the
/// LAPIC isn't mapped yet.
///
/// # SAFETY: LAPIC enabled on this CPU; IRQs may be masked or not
/// (ICR write is non-blocking -- wait_icr_idle handles serialization).
/// # C: O(spin) bounded by hardware delivery latency
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn send_resched_ipi(target_cpu: u32) -> bool {
    let target_apic_id = match ::cpu::hardware_id_for_logical(target_cpu) {
        Some(id) => id,
        None => return false,
    };
    // SAFETY: LAPIC enabled per fn contract; ICR delivery completes asynchronously, wait_icr_idle bounds prior write.
    unsafe { wait_icr_idle(); }
    let lo = build_icr_lo(hal_x86_64::VEC_RESCHED, 0b000, true, false);
    // SAFETY: same -- ICR write triggers IPI delivery to target.
    let ok = unsafe { write_icr(target_apic_id, lo) };
    if ok {
        // SAFETY: same -- ensure ICR settled before caller assumes delivery.
        unsafe { wait_icr_idle(); }
    }
    ok
}

/// Send a diagnostic NMI IPI to `apic_id`. Delivery mode 0b100 (NMI) so
/// it lands through IF=0 — a CPU spinning in a spinlock deadlock with
/// interrupts masked still takes it. The NMI handler (fault.rs, vector 2)
/// prints RIP/regs + current task then iretq-resumes, so a poke at a CPU
/// that wasn't actually wedged is harmless.
/// # SAFETY: LAPIC enabled on this CPU; ICR write serialised by wait_icr_idle.
/// # C: O(spin) bounded by delivery latency
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn send_nmi_ipi(apic_id: u32) -> bool {
    // SAFETY: LAPIC enabled per fn contract; serialise prior ICR write.
    unsafe { wait_icr_idle(); }
    let lo = build_icr_lo(0, 0b100, true, false); // vector ignored for NMI delivery
    // SAFETY: ICR write triggers NMI delivery to the target APIC.
    let ok = unsafe { write_icr(apic_id, lo) };
    if ok {
        // SAFETY: ensure ICR settled before the caller assumes delivery.
        unsafe { wait_icr_idle(); }
    }
    ok
}

/// Poke hook (`sched::diag::nmi`): heartbeats index CPUs by dense logical
/// CPU id, so translate to the x86 APIC id before sending the NMI.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn diag_nmi_poke(cpu: u32) {
    let apic_id = match ::cpu::hardware_id_for_logical(cpu) {
        Some(id) => id,
        None => return,
    };
    // SAFETY: boot enabled the LAPIC before diag hooks are installed.
    unsafe { let _ = send_nmi_ipi(apic_id); }
}

/// Install the cross-CPU backtrace poke hook. Called once at boot.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn install_diag_hooks() {
    sched::diag::nmi::set_poke_hook(diag_nmi_poke);
}

/// Enable the LAPIC on this AP. Same software-enable + APIC-base
/// MSR set as `enable` but without the AlreadyOn early-return:
/// each CPU has its own LAPIC SVR + IA32_APIC_BASE MSR, and the
/// MMIO at `LAPIC_BASE_VA` aliases to this CPU's LAPIC page.
/// Returns this CPU's APIC ID + version.
///
/// # SAFETY: caller is the AP bring-up path; BSP ran `enable`
/// previously so `LAPIC_BASE_VA` is non-zero. Single-writer for
/// this CPU's per-CPU LAPIC state.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn enable_for_ap() -> (u32, u32) {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return (u32::MAX, 0); }
    // SAFETY: rdmsr/wrmsr on IA32_APIC_BASE are privileged but legal at CPL=0; bit 11 is global enable on this CPU's LAPIC.
    unsafe {
        let cur = rdmsr(MSR_IA32_APIC_BASE);
        if (cur & APIC_GLOBAL_ENABLE) == 0 {
            wrmsr(MSR_IA32_APIC_BASE, cur | APIC_GLOBAL_ENABLE);
        }
    }
    // GAP-2 hardening: pick the EOI path for this AP (MSR if in x2APIC mode).
    select_eoi_path();
    // SAFETY: `va` aliases this CPU's LAPIC page; SVR offset within.
    unsafe {
        let svr_addr = (va + REG_SVR as u64) as *mut u32;
        let cur = core::ptr::read_volatile(svr_addr);
        let new = (cur & !0xFF) | SPURIOUS_VECTOR | SVR_ENABLE;
        core::ptr::write_volatile(svr_addr, new);
    }
    // SAFETY: same -- read this AP's APIC id + version.
    unsafe {
        let id  = core::ptr::read_volatile((va + REG_ID as u64) as *const u32);
        let ver = core::ptr::read_volatile((va + REG_VERSION as u64) as *const u32);
        (id >> 24, ver)
    }
}
