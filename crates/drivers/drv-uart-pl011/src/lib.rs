#![no_std]
//! ARM PL011 UART driver (aarch64 MMIO console).
//!
//! drivers-plan D4: extracted from `drv-serial` into its own `drv-*`
//! crate (docs/35§3, one crate per device). The RX path takes the
//! tty-delivery callback as a parameter so this crate has no upward
//! dependency on `drv-serial` (the cycle-break) — `drv-serial` passes
//! its own `deliver` fn into `init`/`rx_poll`.
//!
//! Detection uses the boot-published PL011 Device VA
//! (`hal_aarch64::pl011::base_va`). On non-arm arches this crate is an
//! empty shell so the workspace builds. docs/53 (kernel = glue).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Detected PL011 MMIO base VA. 0 ⇒ no UART bound.
static BASE: AtomicU64 = AtomicU64::new(0);
static PRESENT: AtomicBool = AtomicBool::new(false);

/// True once a PL011 UART has been detected + registered by `init`.
/// # C: O(1)
pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

// ---------------------------------------------------------------- aarch64
#[cfg(target_arch = "aarch64")]
mod imp {
    use super::*;
    const PL011_DR: u64 = 0x00;
    const PL011_FR: u64 = 0x18;
    const FR_RXFE:  u32 = 1 << 4;
    const FR_TXFF:  u32 = 1 << 5;

    fn base() -> u64 { BASE.load(Ordering::Acquire) }

    /// Console TX over PL011.
    /// # C: O(len(bytes))
    pub fn emit(bytes: &[u8]) {
        let va = base(); if va == 0 { return; }
        for &c in bytes {
            let mut n = 0u32;
            // SAFETY: FR read through the published PL011 Device VA.
            while n < 100_000 && (unsafe { core::ptr::read_volatile((va + PL011_FR) as *const u32) } & FR_TXFF) != 0 { n += 1; }
            // SAFETY: DR write through the published PL011 Device VA.
            unsafe { core::ptr::write_volatile((va + PL011_DR) as *mut u32, c as u32); }
        }
    }

    /// Timer-tick RX poll; `dlv` delivers each drained byte.
    /// # SAFETY: reads through the published PL011 Device VA; single-CPU.
    /// # C: O(N_bytes_drained)
    pub unsafe fn rx_poll(dlv: fn(u8)) {
        let va = base(); if va == 0 { return; }
        let mut n = 0;
        while n < 16 {
            // SAFETY: FR read through the PL011 Device VA.
            let fr = unsafe { core::ptr::read_volatile((va + PL011_FR) as *const u32) };
            if (fr & FR_RXFE) != 0 { break; }
            // SAFETY: DR read through the PL011 Device VA.
            let b = unsafe { core::ptr::read_volatile((va + PL011_DR) as *const u32) } as u8;
            dlv(b);
            n += 1;
        }
    }

    /// arm RX is timer-tick polled; MSI/SPI-driven RX is a follow-up.
    /// # C: O(1)
    pub fn rx_isr(_dlv: fn(u8)) {}

    /// Detect the PL011 (boot-published base VA) + register the console
    /// TX. RX is timer-tick polled. `_dev_window_base` unused on arm
    /// (PL011 already device-mapped at boot). `_dlv` unused at init
    /// (passed per-poll instead). Returns true on detection.
    /// # SAFETY: PL011 Device VA published; single-CPU, IRQs masked.
    /// # C: O(1)
    pub unsafe fn init(_bsp_apic: u8, _dev_window_base: u64, _dlv: fn(u8)) -> bool {
        let va = hal_aarch64::pl011::base_va();
        if va == 0 { return false; }
        BASE.store(va, Ordering::Release);
        PRESENT.store(true, Ordering::Release);
        true
    }
}

// --------------------------------------------------------- empty shell
#[cfg(not(target_arch = "aarch64"))]
mod imp {
    /// No PL011 on non-arm arches; TX no-op.
    /// # C: O(1)
    pub fn emit(_bytes: &[u8]) {}
    /// No PL011 on non-arm arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub unsafe fn rx_poll(_dlv: fn(u8)) {}
    /// No PL011 on non-arm arches.
    /// # C: O(1)
    pub fn rx_isr(_dlv: fn(u8)) {}
    /// No PL011 on non-arm arches; detect fails.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub unsafe fn init(_bsp_apic: u8, _dev_window_base: u64, _dlv: fn(u8)) -> bool { false }
}

pub use imp::{emit, init, rx_isr, rx_poll};

// ------------------------------------------------ drv model (D1a)
/// The PL011 console as a drv model driver. `probe` is a no-op — `init`
/// already brought the UART up; the model entry exists for the
/// platform/serial0 device + D1b probe-driven bring-up.
struct UartPl011Drv;
impl drv::Driver for UartPl011Drv {
    fn name(&self) -> &'static str { "pl011-serial" }
    fn matches(&self, dev: &drv::Device) -> bool { dev.bus == "platform" && dev.addr == "serial0" }
}

/// Driver-model handle; name "pl011-serial" matches the platform/serial0
/// device kmain registers. Exposed so `drv-serial::init` registers the
/// per-arch UART driver uniformly.
pub static UART_DRIVER: &dyn drv::Driver = &UartPl011Drv;
