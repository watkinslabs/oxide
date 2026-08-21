use super::regs::{busy_wait_us, read_icr_register, write_icr_register};

// ---------------------------------------------------------------------------
// AP startup IPI primitives per `20§7` / Intel SDM Vol 3 §10.4.
// ---------------------------------------------------------------------------

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

/// Linux `safe_apic_wait_icr_idle()`: wait at most 100 ms for the previous
/// ICR delivery to complete. CPU startup/hotplug must fail and unwind instead
/// of hanging the surviving CPU forever on a broken or absent destination.
/// # SAFETY: caller owns the enabled LAPIC ICR transport with IRQs masked.
/// # C: O(1000 hardware polls), bounded to 100 ms
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn wait_icr_idle_timeout() -> bool {
    let mut tries = 0;
    while tries < 1_000 {
        // SAFETY: forwarded enabled-LAPIC contract.
        let Some(icr) = (unsafe { read_icr_register() }) else { return false; };
        if icr & (1 << 12) == 0 { return true; }
        // Linux waits 100 us between the same 1000 delivery-status polls.
        busy_wait_us(100);
        tries += 1;
    }
    false
}
