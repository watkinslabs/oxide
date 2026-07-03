#![no_std]
//! ARM PL011 UART driver (aarch64 MMIO console).
//!
//! drivers-plan D4: extracted from `drv-serial` into its own `drv-*`
//! crate (docs/35§3, one crate per device). The RX path takes the
//! tty-delivery callback as a parameter so this crate has no upward
//! dependency on `drv-serial` (the cycle-break) — `drv-serial` passes
//! its own `deliver` fn into probe setup.
//!
//! Detection uses the boot-published PL011 Device VA
//! (`hal_aarch64::pl011::base_va`). On non-arm arches this crate is an
//! empty shell so the workspace builds. docs/53 (kernel = glue).

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Detected PL011 MMIO base VA. 0 ⇒ no UART bound.
static BASE: AtomicU64 = AtomicU64::new(0);
static PRESENT: AtomicBool = AtomicBool::new(false);
static BSP_APIC: AtomicU64 = AtomicU64::new(0);
static DEV_WINDOW_BASE: AtomicU64 = AtomicU64::new(0);
static DELIVER: AtomicU64 = AtomicU64::new(0);

#[inline]
fn deliver(b: u8) {
    let p = DELIVER.load(Ordering::Acquire);
    if p == 0 { return; }
    // SAFETY: p was stored from a `fn(u8)` by configure_probe.
    let f: fn(u8) = unsafe { core::mem::transmute(p as usize) };
    f(b);
}

/// True once a PL011 UART has been detected + registered by `init`.
/// # C: O(1)
pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

/// Install boot-probe parameters used when the drv core calls
/// `UartPl011Drv::probe`.
/// # C: O(1)
pub fn configure_probe(bsp_apic: u8, dev_window_base: u64, dlv: fn(u8)) {
    BSP_APIC.store(bsp_apic as u64, Ordering::Release);
    DEV_WINDOW_BASE.store(dev_window_base, Ordering::Release);
    DELIVER.store(dlv as usize as u64, Ordering::Release);
}

// ---------------------------------------------------------------- aarch64
#[cfg(target_arch = "aarch64")]
mod imp {
    use super::*;
    const PL011_DR: u64 = 0x00;
    const PL011_FR: u64 = 0x18;
    const FR_RXFE:  u32 = 1 << 4;
    const FR_TXFF:  u32 = 1 << 5;
    const PL011_INTID: u32 = 33;

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

    fn drain_rx(dlv: fn(u8)) {
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

    /// No timer polling: PL011 RX is delivered by SPI 33.
    /// # SAFETY: shell retained for drv-serial API shape; no side effects.
    /// # C: O(1)
    pub unsafe fn rx_poll(_dlv: fn(u8)) {}

    /// RX interrupt drain.
    /// # C: O(bytes pending)
    pub fn rx_isr(dlv: fn(u8)) {
        drain_rx(dlv);
        // SAFETY: called from the GIC dispatcher for PL011 INTID 33.
        unsafe { hal_aarch64::pl011::ack_rx_irq(); }
    }

    fn rx_isr_irq() { rx_isr(super::deliver); }

    /// Detect the PL011 (boot-published base VA) + register the console
    /// TX/RX. `_dev_window_base` unused on arm (PL011 already device-mapped
    /// at boot). Returns true on detection.
    /// # SAFETY: PL011 Device VA published; single-CPU, IRQs masked.
    /// # C: O(1)
    pub(super) unsafe fn init(_bsp_apic: u8, _dev_window_base: u64, dlv: fn(u8)) -> bool {
        let va = hal_aarch64::pl011::base_va();
        if va == 0 { return false; }
        BASE.store(va, Ordering::Release);
        DELIVER.store(dlv as usize as u64, Ordering::Release);
        if arch_irq::request_arm_irq_handler(PL011_INTID, rx_isr_irq).is_err() {
            BASE.store(0, Ordering::Release);
            return false;
        }
        // SAFETY: GIC is up; PL011 owns SPI 33 and it is level-sensitive.
        unsafe { arch_irq::gic::enable_intid_level(PL011_INTID); }
        // SAFETY: PL011 was enabled by boot mapping and is now owned by this driver.
        unsafe { hal_aarch64::pl011::enable_rx_irq(); }
        PRESENT.store(true, Ordering::Release);
        true
    }

    /// Clear the bound PL011 state. The boot mapping remains owned by the
    /// platform/early MMU setup; this driver stops publishing the UART as bound.
    /// # SAFETY: called by driver-core remove; no concurrent probe/remove.
    /// # C: O(1)
    pub(super) unsafe fn remove() {
        // SAFETY: driver-core remove owns PL011 teardown.
        unsafe { hal_aarch64::pl011::disable_rx_irq(); }
        // SAFETY: PL011 owns SPI 33 while bound.
        unsafe { arch_irq::gic::disable_intid(PL011_INTID); }
        let _ = arch_irq::free_arm_irq_handler(PL011_INTID);
        BASE.store(0, Ordering::Release);
        PRESENT.store(false, Ordering::Release);
    }

    /// Stop PL011 RX interrupt delivery for terminal system shutdown while
    /// keeping the console TX path bound for late shutdown logging.
    /// # SAFETY: called by driver-core shutdown; no concurrent probe/remove.
    /// # C: O(1)
    pub(super) unsafe fn shutdown() {
        // SAFETY: driver-core shutdown owns PL011 terminal quiesce.
        unsafe { hal_aarch64::pl011::disable_rx_irq(); }
        // SAFETY: PL011 owns SPI 33 while bound.
        unsafe { arch_irq::gic::disable_intid(PL011_INTID); }
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
    pub(super) unsafe fn init(_bsp_apic: u8, _dev_window_base: u64, _dlv: fn(u8)) -> bool { false }
    /// No PL011 on non-arm arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn remove() {}
    /// No PL011 on non-arm arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn shutdown() {}
}

pub use imp::{emit, rx_isr, rx_poll};

// ------------------------------------------------ drv model
/// The PL011 console as a drv model driver. Probe performs detection; a
/// missing boot-published PL011 leaves platform/serial0 unbound.
struct UartPl011Drv;
impl drv::Driver for UartPl011Drv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "pl011-serial" }
    fn matches(&self, dev: &drv::Device) -> bool { dev.bus == "platform" && dev.addr == "serial0" }
    fn probe(&self, _dev: &Arc<drv::Device>) -> drv::KResult<()> {
        if present() {
            return Err(drv::Error::Busy);
        }
        let p = DELIVER.load(Ordering::Acquire);
        if p == 0 {
            return Err(drv::Error::ProbeFailed);
        }
        // SAFETY: p was stored from a `fn(u8)` by configure_probe.
        let dlv: fn(u8) = unsafe { core::mem::transmute(p as usize) };
        let bsp_apic = BSP_APIC.load(Ordering::Acquire) as u8;
        let dev_window_base = DEV_WINDOW_BASE.load(Ordering::Acquire);
        // SAFETY: driver-core bind runs on the same boot path that previously
        // called init directly: PL011 Device VA published, single-CPU.
        if unsafe { imp::init(bsp_apic, dev_window_base, dlv) } {
            Ok(())
        } else {
            Err(drv::Error::ProbeFailed)
        }
    }

    fn remove(&self, _dev: &drv::Device) {
        // SAFETY: driver-core remove owns the bound platform device teardown.
        unsafe { imp::remove(); }
    }

    fn shutdown(&self, _dev: &drv::Device) {
        // SAFETY: driver-core shutdown owns terminal platform-device quiesce.
        unsafe { imp::shutdown(); }
    }
}

/// Driver-model handle; name "pl011-serial" matches the platform/serial0
/// device kmain registers. Exposed so `drv-serial::init` registers the
/// per-arch UART driver uniformly.
pub static UART_DRIVER: &dyn drv::Driver = &UartPl011Drv;
