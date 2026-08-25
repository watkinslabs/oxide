#![no_std]
//! 16550/8250 UART driver (x86_64 COM1 / ACPI SPCR I/O port).
//!
//! drivers-plan D4: extracted from `drv-serial` into its own `drv-*`
//! crate (docs/35§3, one crate per device). The RX path takes the
//! tty-delivery callback as a parameter so this crate has no upward
//! dependency on `drv-serial` (the cycle-break) — `drv-serial` passes
//! its own `deliver` fn into `init`.
//!
//! Detection is Linux-compliant: the UART is probed, never assumed.
//! ACPI SPCR-elected I/O port wins; else the legacy 8250 scratch probe
//! at COM1 (0x3F8). On non-x86 arches this crate is an empty shell so
//! the workspace builds. docs/53 (kernel = glue).

extern crate alloc;

#[cfg(any(target_arch = "x86_64", test))]
mod tx;
/// Sleep callbacks (`32a§5` steps 6 and 8).
pub mod pm;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_arch = "x86_64")]
use sync::{LockClass, Spinlock};

#[cfg(target_arch = "x86_64")]
struct UartPort;
#[cfg(target_arch = "x86_64")]
impl LockClass for UartPort {
    fn rank() -> u16 { 121 }
    fn name() -> &'static str { "UartPort" }
}

/// Serializes the xmit ring and every transaction against the port's aliased
/// register window. A divisor transaction with DLAB set excludes both the IRQ
/// FIFO fill and another writer's IER/THR access.
#[cfg(target_arch = "x86_64")]
static PORT: Spinlock<tx::TxEngine<{ tx::TX_RING_CAPACITY }>, UartPort>
    = Spinlock::new(tx::TxEngine::new());

/// Detected COM I/O base (x86 port). 0 ⇒ no UART bound.
#[cfg(target_arch = "x86_64")]
static BASE: AtomicU64 = AtomicU64::new(0);
static PRESENT: AtomicBool = AtomicBool::new(false);
static RX_ENABLED: AtomicBool = AtomicBool::new(false);
static BSP_APIC: AtomicU64 = AtomicU64::new(0);
static DEV_WINDOW_BASE: AtomicU64 = AtomicU64::new(0);
/// SysRq arm deadline for this hardware port.
static SYSRQ_ARMED_UNTIL_NS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static IRQ_VEC: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static IRQ_PIN: AtomicU64 = AtomicU64::new(u64::MAX);
/// tty-delivery callback, stored from `init`'s parameter so
/// the bare-`fn()` MSI handler trampoline can reach it without args.
static DELIVER: AtomicU64 = AtomicU64::new(0);
/// Line requested by the last serial `console=` token, packed as
/// baud:32 | parity:8 | bits:8 | flow:1. Stored before probe and consumed by
/// the real UART owner after it publishes the detected base.
static CONSOLE_LINE: AtomicU64 = AtomicU64::new(0);

/// 16550 LCR data-width/parity bits for one Linux console option tuple.
/// One stop bit is the console default. # C: O(1)
pub const fn line_control_bits(parity: u8, bits: u8) -> u8 {
    let width = match bits { 5 => 0, 6 => 1, 7 => 2, _ => 3 };
    let parity = match parity {
        b'o' => 1 << 3,
        b'e' => (1 << 3) | (1 << 4),
        _ => 0,
    };
    width | parity
}

/// 16550 automatic CTS/RTS enable bit. RTS itself remains asserted in MCR;
/// AFE decides whether hardware may modulate it. # C: O(1)
pub const fn modem_control_bits(flow: bool) -> u8 { if flow { 1 << 5 } else { 0 } }

/// Retain the parsed runtime-console line until hardware probe. # C: O(1)
pub fn configure_line(baud: u32, parity: u8, bits: u8, flow: bool) {
    let packed = u64::from(baud) | (u64::from(parity) << 32)
        | (u64::from(bits) << 40) | (u64::from(flow) << 48);
    CONSOLE_LINE.store(packed, Ordering::Release);
}

#[cfg(target_arch = "x86_64")]
fn configured_line() -> (u32, u8, u8, bool) {
    let p = CONSOLE_LINE.load(Ordering::Acquire);
    (p as u32, (p >> 32) as u8, (p >> 40) as u8, (p >> 48) & 1 != 0)
}

/// True once a 16550 UART has been detected + registered by `init`.
/// # C: O(1)
pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

/// True while runtime RX interrupt delivery is allowed. Shutdown clears this
/// before masking hardware so a late/spurious vector cannot drain bytes after
/// terminal quiesce starts.
/// # C: O(1)
pub fn rx_enabled() -> bool { RX_ENABLED.load(Ordering::Acquire) }

/// Install boot-probe parameters used when the drv core calls
/// `Uart16550Drv::probe`.
/// # C: O(1)
pub fn configure_probe(bsp_apic: u8, dev_window_base: u64,
    dlv: fn(&'static AtomicU64, u8)) {
    SYSRQ_ARMED_UNTIL_NS.store(0, Ordering::Relaxed);
    BSP_APIC.store(bsp_apic as u64, Ordering::Release);
    DEV_WINDOW_BASE.store(dev_window_base, Ordering::Release);
    DELIVER.store(dlv as usize as u64, Ordering::Release);
}

/// Only the x86 `imp`'s bare-`fn()` IRQ trampoline needs this indirection;
/// the non-x86 shell has no RX path.
#[cfg(target_arch = "x86_64")]
#[inline]
fn deliver(b: u8) {
    let p = DELIVER.load(Ordering::Acquire);
    if p == 0 { return; }
    // SAFETY: p was stored from this exact function-pointer type.
    let f: fn(&'static AtomicU64, u8) = unsafe { core::mem::transmute(p as usize) };
    f(&SYSRQ_ARMED_UNTIL_NS, b);
}

// ---------------------------------------------------------------- x86_64
#[cfg(target_arch = "x86_64")]
#[path = "imp/x86.rs"]
mod imp;

// --------------------------------------------------------- empty shell
#[cfg(not(target_arch = "x86_64"))]
mod imp {
    /// No 16550 on non-x86 arches; TX no-op.
    /// # C: O(1)
    pub fn emit(_bytes: &[u8]) {}
    /// No 16550 on non-x86 arches; baud no-op.
    /// # C: O(1)
    pub fn set_baud(_baud: u32) {}
    /// No 16550 on non-x86 arches; line setup no-op.
    pub fn set_line(_baud: u32, _parity: u8, _bits: u8, _flow: bool) {}
    /// No 16550 on non-x86 arches.
    /// # C: O(1)
    pub fn rx_isr() {}
    /// No 16550 on non-x86 arches; detect fails.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn init(_bsp_apic: u8, _dev_window_base: u64,
        _dlv: fn(&'static core::sync::atomic::AtomicU64, u8)) -> bool { false }
    /// No 16550 on non-x86 arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn remove() {}
    /// No 16550 on non-x86 arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn shutdown() {}
    /// No 16550 on non-x86 arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub unsafe fn console_to_polled() {}
}

pub use imp::{console_to_polled, emit, rx_isr, set_baud, set_line};

// ------------------------------------------------ drv model
/// The 16550 console as a drv model driver. Probe performs detection and
/// IRQ setup; a missing UART leaves platform/serial0 unbound.
struct Uart16550Drv;
impl drv::Driver for Uart16550Drv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "8250-serial" }
    fn matches(&self, dev: &drv::Device) -> bool { dev.bus == "platform" && dev.addr == "serial0" }
    fn probe(&self, _dev: &Arc<drv::Device>) -> drv::KResult<()> {
        if present() {
            return Err(drv::Error::Busy);
        }
        let p = DELIVER.load(Ordering::Acquire);
        if p == 0 {
            return Err(drv::Error::ProbeFailed);
        }
        // SAFETY: p was stored from this exact function-pointer type.
        let dlv: fn(&'static AtomicU64, u8) = unsafe { core::mem::transmute(p as usize) };
        let bsp_apic = BSP_APIC.load(Ordering::Acquire) as u8;
        let dev_window_base = DEV_WINDOW_BASE.load(Ordering::Acquire);
        // SAFETY: driver-core bind runs on the same boot path that previously
        // called init directly: post-ACPI/LAPIC, MmuOps live, IRQs masked.
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

    fn pm(&self) -> Option<&'static drv::DevPmOps> { Some(&pm::PM_OPS) }

    fn shutdown(&self, _dev: &drv::Device) {
        // SAFETY: driver-core shutdown owns terminal platform-device quiesce.
        unsafe { imp::shutdown(); }
    }
}



/// Driver-model handle; name "8250-serial" matches the platform/serial0
/// device kmain registers. Exposed so `drv-serial::init` registers the
/// per-arch UART driver uniformly.
pub static UART_DRIVER: &dyn drv::Driver = &Uart16550Drv;

#[cfg(test)]
#[path = "tests/uart.rs"]
mod tests;
