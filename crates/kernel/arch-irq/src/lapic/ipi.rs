use super::regs::{read_icr_register, write_icr_register};

// ---------------------------------------------------------------------------
// AP startup IPI primitives per `20§7` / Intel SDM Vol 3 §10.4.
// ---------------------------------------------------------------------------

/// Build an ICR-low value. Pure helper -- hosted-testable.
/// Layout per Intel SDM Vol 3 §10.6.1:
///   bits 0-7: vector
///   bits 8-10: delivery mode
///   bit 11: dest mode (0=physical)
///   bit 14: level (1=assert)
///   bit 15: trigger (0=edge, 1=level)
///   bits 18-19: dest shorthand (00 = explicit dest in ICR-hi)
/// # C: O(1)
pub fn build_icr_lo(vector: u8, delivery: u8, level_assert: bool, level_trigger: bool) -> u32 {
    let mut v = vector as u32;
    v |= ((delivery as u32) & 0x7) << 8;
    if level_assert  { v |= 1 << 14; }
    if level_trigger { v |= 1 << 15; }
    v
}

/// INIT-IPI value (level-asserted edge-trigger): 0x4500. Writing this
/// to ICR-low while ICR-high holds the target APIC ID asserts INIT
/// on the target. AP enters wait-for-SIPI state.
/// # C: O(1)
pub fn icr_lo_init_assert() -> u32 { build_icr_lo(0, 0b101, true, false) }

/// SIPI ICR-low value: 0x4600 | startup_page. The startup page is the
/// real-mode segment (4 KiB units, < 1 MiB) holding the AP trampoline.
/// AP starts execution at `page << 12`.
/// # C: O(1)
pub fn icr_lo_sipi(startup_page: u8) -> u32 { build_icr_lo(startup_page, 0b110, true, false) }

/// Write the LAPIC ICR. Triggers IPI delivery to `target_apic_id`.
/// Returns false if the LAPIC isn't mapped yet.
///
/// # SAFETY: caller asserts the LAPIC is enabled, the ICR write is
/// the appropriate IPI for the AP's current state (INIT first, then
/// SIPI per Intel SDM Vol 3 §10.4.4.1), and IRQs are masked while
/// the ICR delivery-pending bit is being polled by `wait_icr_idle`.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn write_icr(target_apic_id: u32, lo: u32) -> bool {
    // SAFETY: this forwards the caller's serialized ICR-transition contract.
    unsafe { write_icr_register(target_apic_id, lo) }
}

/// Spin until the LAPIC ICR's delivery-status bit (bit 12 of low DW)
/// clears -- the previous IPI has been accepted by the bus.
///
/// # SAFETY: caller is the boot path during AP startup; LAPIC is
/// mapped; IRQs masked.
/// # C: O(spin) -- bounded by hardware delivery latency
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn wait_icr_idle() {
    loop {
        // SAFETY: this forwards the caller's enabled-LAPIC contract to the register backend.
        let Some(icr) = (unsafe { read_icr_register() }) else { return; };
        if (icr & (1 << 12)) == 0 { break; }
        // SAFETY: spin loop hint; pause has no side effect outside microarch hinting.
        unsafe { core::arch::asm!("pause", options(nomem, nostack, preserves_flags)); }
    }
}
