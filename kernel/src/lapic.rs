// Local APIC bring-up per `22§6` (x86_64 only).
//
// Maps LAPIC's MMIO page (phys typically 0xFEE00000 from MADT) into
// kernel space via the device mapper, asserts IA32_APIC_BASE.E, and
// programs the Spurious Interrupt Vector Register's software-enable
// bit. Reads back the APIC ID + version as a sanity check.
//
// Timer LVT + IRQ wiring rides alongside the IDT vector binding +
// EOI helper that follow this PR.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use core::arch::asm;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
const REG_ID:      usize = 0x020;
#[cfg(target_arch = "x86_64")]
const REG_VERSION: usize = 0x030;
#[cfg(target_arch = "x86_64")]
const REG_SVR:     usize = 0x0F0;
#[cfg(target_arch = "x86_64")]
const REG_LVT_TIMER:  usize = 0x320;
#[cfg(target_arch = "x86_64")]
const REG_TIMER_INIT: usize = 0x380;
#[cfg(target_arch = "x86_64")]
const REG_TIMER_CUR:  usize = 0x390;
#[cfg(target_arch = "x86_64")]
const REG_TIMER_DIV:  usize = 0x3E0;

/// SVR bit 8: APIC software enable.
#[cfg(target_arch = "x86_64")]
const SVR_ENABLE:  u32 = 1 << 8;

/// Default spurious-interrupt vector. Lowest 4 bits must be 1 on
/// pre-Pentium-4 hardware; we set 0xFF for compatibility.
#[cfg(target_arch = "x86_64")]
const SPURIOUS_VECTOR: u32 = 0xFF;

/// IA32_APIC_BASE MSR (0x1B). Bit 11 = global enable.
#[cfg(target_arch = "x86_64")]
const MSR_IA32_APIC_BASE: u32 = 0x1B;
#[cfg(target_arch = "x86_64")]
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;

/// Mapped kernel VA after `enable` runs. `0` until then.
#[cfg(target_arch = "x86_64")]
static LAPIC_BASE_VA: AtomicU64 = AtomicU64::new(0);

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
    // Make sure IA32_APIC_BASE.E is set (Limine leaves it on, but
    // be defensive — bit 11 is the global enable).
    // SAFETY: rdmsr/wrmsr on IA32_APIC_BASE are privileged but
    // legal at CPL=0; bit 11 is the well-defined global-enable bit.
    unsafe {
        let cur = rdmsr(MSR_IA32_APIC_BASE);
        if (cur & APIC_GLOBAL_ENABLE) == 0 {
            wrmsr(MSR_IA32_APIC_BASE, cur | APIC_GLOBAL_ENABLE);
        }
    }
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

/// Configure the LAPIC timer in one-shot mode, masked (no IRQ
/// delivery yet — this is purely a hardware-tick smoke). Returns
/// the current count register reading after a brief busy spin so
/// the caller can confirm the counter is decrementing.
///
/// `initial_count` is loaded into the timer's Initial Count
/// Register; with divide=0b1011 (1) the LAPIC bus clock decrements
/// the count register by one per cycle.
///
/// # SAFETY: caller asserts `enable` has run and `LAPIC_BASE_VA`
/// is non-zero. Single-CPU, IRQ-off.
/// # C: O(spin)
/// # Ctx: pre-init, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_smoke(initial_count: u32) -> Option<(u32, u32)> {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return None; }
    // SAFETY: LAPIC was previously mapped Device-attr; `va` lives
    // inside that 4 KiB page.
    let (a, b) = unsafe {
        // Divide config: `1011` = divide-by-1 (full bus rate).
        core::ptr::write_volatile((va + REG_TIMER_DIV  as u64) as *mut u32, 0b1011);
        // Mask LVT timer (bit 16 = 1) — no IRQ delivery; just count.
        // Vector 0x40 is set so when we later unmask, it has a valid value.
        core::ptr::write_volatile((va + REG_LVT_TIMER as u64) as *mut u32, 0x40 | (1 << 16));
        // Load initial count — the timer starts decrementing.
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, initial_count);
        let a = core::ptr::read_volatile((va + REG_TIMER_CUR as u64) as *const u32);
        // Brief busy spin so the count visibly decreases.
        for _ in 0..1024 { core::hint::spin_loop(); }
        let b = core::ptr::read_volatile((va + REG_TIMER_CUR as u64) as *const u32);
        // Stop the timer (initial count = 0 disables one-shot).
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, 0);
        (a, b)
    };
    Some((a, b))
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn rdmsr(idx: u32) -> u64 {
    let lo: u32; let hi: u32;
    // SAFETY: rdmsr at CPL=0 with valid MSR index; no memory effect.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") idx,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn wrmsr(idx: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: wrmsr at CPL=0 with valid MSR index + caller-validated value; no memory effect.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") idx,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lapic_status_distinct() {
        let a = LapicStatus::AlreadyOn;
        let b = LapicStatus::Enabled { apic_id: 0, version: 0 };
        assert_ne!(a, b);
    }
}
