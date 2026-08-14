//! x86 FADT-authorised S5 register writes.

use firmware::acpi::{Gas, PowerOffAction, SPACE_SYSTEM_IO, SPACE_SYSTEM_MEMORY};
use hal::TimerOps;
use crate::poweroff_plan::{legacy_writes, retry_write};

const S5_RETRY_NS: u64 = 10_000_000_000;
const REDUCED_SLEEP_TYPE_SHIFT: u8 = 2;
const REDUCED_SLEEP_ENABLE: u8 = 0x20;
const REDUCED_WAKE_STATUS: u8 = 0x80;

/// # SAFETY: caller owns the terminal machine transition and performs a firmware-authorised port read.
unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    // SAFETY: the terminal power path is CPL0 and the FADT admitted this I/O port.
    unsafe { core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}

/// # SAFETY: caller owns the terminal machine transition and performs a firmware-authorised port write.
unsafe fn outw(port: u16, value: u16) {
    // SAFETY: the terminal power path is CPL0 and the FADT admitted this I/O port.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)); }
}

/// # SAFETY: caller owns the terminal machine transition and performs a firmware-authorised port write.
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the terminal power path is CPL0 and the FADT admitted this I/O port.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)); }
}

fn mapped(gas: Gas, bytes: u64) -> Option<u64> {
    let page = gas.address & !0xfff;
    let offset = gas.address.checked_sub(page)?;
    let count = offset.checked_add(bytes)?.checked_add(0xfff)?.checked_div(0x1000)?;
    // SAFETY: FADT admitted a system-memory control register and the terminal path owns its access.
    let va = unsafe { mmio_map::map_pages(page, count) };
    (va != 0).then_some(va.checked_add(offset)?)
}

fn read_pm1(gas: Gas) -> Option<u16> {
    match gas.space_id {
        SPACE_SYSTEM_IO => {
            let port = u16::try_from(gas.address).ok()?;
            port.checked_add(1)?;
            // SAFETY: `gas` was admitted from the FADT as a terminal PM1 control register.
            Some(unsafe { inw(port) })
        }
        SPACE_SYSTEM_MEMORY => {
            let va = mapped(gas, 2)?;
            // SAFETY: `mapped` returns a live two-byte mapping for this FADT register.
            Some(unsafe { core::ptr::read_volatile(va as *const u16) })
        }
        _ => None,
    }
}

fn write_pm1(gas: Gas, value: u16) -> bool {
    match gas.space_id {
        SPACE_SYSTEM_IO => {
            let Some(port) = u16::try_from(gas.address).ok().and_then(|port| port.checked_add(1).map(|_| port)) else { return false; };
            // SAFETY: `gas` was admitted from the FADT as a terminal PM1 control register.
            unsafe { outw(port, value); }
            true
        }
        SPACE_SYSTEM_MEMORY => {
            let Some(va) = mapped(gas, 2) else { return false; };
            // SAFETY: `mapped` returns a live two-byte mapping for this FADT register.
            unsafe { core::ptr::write_volatile(va as *mut u16, value); }
            true
        }
        _ => false,
    }
}

fn write_byte(gas: Gas, value: u8) -> bool {
    match gas.space_id {
        SPACE_SYSTEM_IO => {
            let Some(port) = u16::try_from(gas.address).ok() else { return false; };
            // SAFETY: `gas` was admitted from the FADT as a terminal sleep register.
            unsafe { outb(port, value); }
            true
        }
        SPACE_SYSTEM_MEMORY => {
            let Some(va) = mapped(gas, 1) else { return false; };
            // SAFETY: `mapped` returns a live byte mapping for this FADT register.
            unsafe { core::ptr::write_volatile(va as *mut u8, value); }
            true
        }
        _ => false,
    }
}

fn legacy(pm1a: Gas, pm1b: Option<Gas>, type_a: u8, type_b: u8) {
    let Some(base) = read_pm1(pm1a) else { return; };
    let writes = legacy_writes(base, type_a, type_b);
    if !write_pm1(pm1a, writes.first_a) { return; }
    if pm1b.is_some_and(|register| !write_pm1(register, writes.first_b)) { return; }
    if !write_pm1(pm1a, writes.enable_a) { return; }
    if pm1b.is_some_and(|register| !write_pm1(register, writes.enable_b)) { return; }
    let deadline = hal_x86_64::X86TimerOps::monotonic_ns().0.saturating_add(S5_RETRY_NS);
    while hal_x86_64::X86TimerOps::monotonic_ns().0 < deadline { core::hint::spin_loop(); }
    if let Some(current) = read_pm1(pm1a) { let _ = write_pm1(pm1a, retry_write(current)); }
    if let Some(register) = pm1b { if let Some(current) = read_pm1(register) { let _ = write_pm1(register, retry_write(current)); } }
}

fn reduced(control: Gas, status: Gas, sleep_type: u8) {
    let _ = write_byte(status, REDUCED_WAKE_STATUS);
    let _ = write_byte(control, (sleep_type << REDUCED_SLEEP_TYPE_SHIFT) | REDUCED_SLEEP_ENABLE);
}

/// Perform the FADT-authorised S5 transition if firmware published one. # C: O(1)
pub fn enter_s5() {
    match firmware::poweroff_action() {
        Some(PowerOffAction::Legacy { pm1a_control, pm1b_control, sleep_type_a, sleep_type_b }) => {
            klog::announce("power_s5 legacy");
            legacy(pm1a_control, pm1b_control, sleep_type_a, sleep_type_b);
        }
        Some(PowerOffAction::Reduced { sleep_control, sleep_status, sleep_type }) => {
            klog::announce("power_s5 reduced");
            reduced(sleep_control, sleep_status, sleep_type);
        }
        None => klog::announce("power_s5 unavailable"),
    }
}
