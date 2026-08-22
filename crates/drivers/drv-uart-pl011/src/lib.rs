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

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;

/// Sleep callbacks (`32a§5` steps 6 and 8).
pub mod pm;
pub mod rx;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use sync::{LockClass, Spinlock};

struct UartPort;
impl LockClass for UartPort {
    fn rank() -> u16 { 121 }
    fn name() -> &'static str { "UartPort" }
}

/// Serializes TX with baud reprogramming on the one hardware register file.
static PORT: Spinlock<(), UartPort> = Spinlock::new(());

/// PL011 reference clock (`UARTCLK`) fallback / test reference. qemu `virt`
/// wires the PL011 to a fixed 24 MHz clock (also the near-universal AMBA PL011
/// rate). The live rate is resolved from the DTB clock tree at boot
/// (`boot-aarch64::dtb::pl011_clock_hz` → `hal_aarch64::pl011::set_uartclk_hz`)
/// and read by `set_baud` via `hal_aarch64::pl011::uartclk_hz()`; this constant
/// is the seed/fallback and the divisor test's reference rate. (The live rate
/// lives in `hal_aarch64::pl011`; this is only the documented reference/test
/// constant, so it is unused in a non-test host build.)
#[allow(dead_code)]
const UARTCLK_HZ: u32 = 24_000_000;

/// PL011 baud divisor (Linux `pl011_calc_divisor`): the 16×-oversampled clock
/// yields a 6.6 fixed-point divisor — `IBRD` = integer part, `FBRD` = the 6
/// fractional bits. `div = round(UARTCLK*4 / baud)` (×4 because 16× oversample
/// over the 6-bit fraction = ÷64 → ×4 net), then `IBRD = div>>6`, `FBRD = div&63`.
/// `baud==0` ⇒ (0,0) (caller treats B0 as "leave current"). Pure + host-tested.
/// # C: O(1)
pub fn pl011_divisor(uartclk: u32, baud: u32) -> (u32, u32) {
    if baud == 0 { return (0, 0); }
    let div = ((uartclk as u64) * 4 + (baud as u64) / 2) / baud as u64;
    ((div >> 6) as u32, (div & 0x3f) as u32)
}

/// Detected PL011 MMIO base VA. 0 ⇒ no UART bound.
static BASE: AtomicU64 = AtomicU64::new(0);
static PRESENT: AtomicBool = AtomicBool::new(false);
static RX_ENABLED: AtomicBool = AtomicBool::new(false);
static BSP_APIC: AtomicU64 = AtomicU64::new(0);
static DEV_WINDOW_BASE: AtomicU64 = AtomicU64::new(0);
static DELIVER: AtomicU64 = AtomicU64::new(0);
/// SysRq arm deadline for this hardware port.
static SYSRQ_ARMED_UNTIL_NS: AtomicU64 = AtomicU64::new(0);
static CONSOLE_LINE: AtomicU64 = AtomicU64::new(0);

/// PL011 LCRH width/parity bits for one Linux console option tuple. # C: O(1)
pub const fn line_control_bits(parity: u8, bits: u8) -> u32 {
    let width = match bits { 5 => 0, 6 => 1, 7 => 2, _ => 3 } << 5;
    let parity = match parity {
        b'o' => 1 << 1,
        b'e' => (1 << 1) | (1 << 2),
        _ => 0,
    };
    width | parity
}

/// PL011 CR hardware CTS/RTS bits. # C: O(1)
pub const fn flow_control_bits(flow: bool) -> u32 {
    if flow { (1 << 15) | (1 << 14) } else { 0 }
}

/// Retain the parsed runtime-console line until hardware probe. # C: O(1)
pub fn configure_line(baud: u32, parity: u8, bits: u8, flow: bool) {
    let packed = u64::from(baud) | (u64::from(parity) << 32)
        | (u64::from(bits) << 40) | (u64::from(flow) << 48);
    CONSOLE_LINE.store(packed, Ordering::Release);
}

#[cfg(target_arch = "aarch64")]
fn configured_line() -> (u32, u8, u8, bool) {
    let p = CONSOLE_LINE.load(Ordering::Acquire);
    (p as u32, (p >> 32) as u8, (p >> 40) as u8, (p >> 48) & 1 != 0)
}

#[inline]
fn deliver(b: u8) {
    let p = DELIVER.load(Ordering::Acquire);
    if p == 0 { return; }
    // SAFETY: p was stored from this exact function-pointer type.
    let f: fn(&'static AtomicU64, u8) = unsafe { core::mem::transmute(p as usize) };
    f(&SYSRQ_ARMED_UNTIL_NS, b);
}

/// True once a PL011 UART has been detected + registered by `init`.
/// # C: O(1)
pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

/// True while runtime RX interrupt delivery is allowed. Shutdown clears this
/// before masking hardware so a late/spurious INTID cannot drain bytes after
/// terminal quiesce starts.
/// # C: O(1)
pub fn rx_enabled() -> bool { RX_ENABLED.load(Ordering::Acquire) }

/// Install boot-probe parameters used when the drv core calls
/// `UartPl011Drv::probe`.
/// # C: O(1)
pub fn configure_probe(bsp_apic: u8, dev_window_base: u64,
    dlv: fn(&'static AtomicU64, u8)) {
    SYSRQ_ARMED_UNTIL_NS.store(0, Ordering::Relaxed);
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
    const PL011_IBRD: u64 = 0x24;
    const PL011_FBRD: u64 = 0x28;
    const PL011_LCRH: u64 = 0x2C;
    const PL011_CR:   u64 = 0x30;
    const FR_RXFE:  u32 = 1 << 4;
    const FR_TXFF:  u32 = 1 << 5;
    const FR_BUSY:  u32 = 1 << 3;
    const CR_UARTEN: u32 = 1 << 0;
    const PL011_INTID: u32 = 33;

    fn base() -> u64 { BASE.load(Ordering::Acquire) }

    /// Console TX over PL011.
    /// # C: O(len(bytes))
    pub fn emit(bytes: &[u8]) {
        let va = base(); if va == 0 { return; }
        let _port = PORT.lock_irqsave::<hal_aarch64::ArmIrqGate>();
        for &c in bytes {
            let mut n = 0u32;
            // SAFETY: FR read through the published PL011 Device VA.
            while n < 100_000 && (unsafe { core::ptr::read_volatile((va + PL011_FR) as *const u32) } & FR_TXFF) != 0 { n += 1; }
            // SAFETY: DR write through the published PL011 Device VA.
            unsafe { core::ptr::write_volatile((va + PL011_DR) as *mut u32, c as u32); }
        }
    }

    /// Nothing to switch: this console's writes are already synchronous —
    /// every byte is polled out against the FIFO-full flag with no queue and no
    /// interrupt in the path. Present so the caller does not have to know which
    /// architecture it is on.
    /// # SAFETY: no side effects.
    /// # C: O(1)
    pub unsafe fn console_to_polled() {}

    /// Reprogram the line baud (TCSETS `c_ospeed`) — Linux `pl011_set_termios`
    /// → `pl011_setup_baud`. Sequence per the PL011 TRM: disable the UART, wait
    /// for the in-flight char to drain (FR.BUSY clear), program IBRD/FBRD, re-
    /// write LCRH to latch the new divisor, then restore CR (re-enabling with the
    /// prior 8N1/FIFO bits preserved). `UARTCLK` is the DTB-resolved reference
    /// rate (`hal_aarch64::pl011::uartclk_hz()`, 24 MHz fallback). `baud==0` (B0)
    /// leaves the current rate.
    /// # SAFETY: MMIO through the published PL011 Device VA; single register
    ///   dance, no concurrent UART reconfigure (TCSETS is serialized per-tty).
    /// # C: O(1) + brief BUSY spin
    pub fn set_baud(baud: u32) {
        let va = base(); if va == 0 || baud == 0 { return; }
        let (ibrd, fbrd) = super::pl011_divisor(hal_aarch64::pl011::uartclk_hz(), baud);
        let _port = PORT.lock_irqsave::<hal_aarch64::ArmIrqGate>();
        // SAFETY: CR/LCRH read + baud reprogram through the published PL011 VA.
        unsafe {
            let cr = core::ptr::read_volatile((va + PL011_CR) as *const u32);
            let lcrh = core::ptr::read_volatile((va + PL011_LCRH) as *const u32);
            // Disable the UART, then wait for the current character to finish.
            core::ptr::write_volatile((va + PL011_CR) as *mut u32, cr & !CR_UARTEN);
            let mut n = 0u32;
            while n < 100_000 && (core::ptr::read_volatile((va + PL011_FR) as *const u32) & FR_BUSY) != 0 { n += 1; }
            // Program the new divisor; a write to LCRH latches IBRD/FBRD.
            core::ptr::write_volatile((va + PL011_IBRD) as *mut u32, ibrd);
            core::ptr::write_volatile((va + PL011_FBRD) as *mut u32, fbrd);
            core::ptr::write_volatile((va + PL011_LCRH) as *mut u32, lcrh);
            // Restore CR (re-enables with the prior line/FIFO/TX/RX bits intact).
            core::ptr::write_volatile((va + PL011_CR) as *mut u32, cr);
        }
    }

    /// Apply the complete runtime-console line setup after probe. # C: O(1)
    pub fn set_line(baud: u32, parity: u8, bits: u8, flow: bool) {
        let va = base(); if va == 0 || baud == 0 { return; }
        let (ibrd, fbrd) = super::pl011_divisor(hal_aarch64::pl011::uartclk_hz(), baud);
        let _port = PORT.lock_irqsave::<hal_aarch64::ArmIrqGate>();
        // SAFETY: one serialized disable/drain/configure/restore transaction.
        unsafe {
            let cr = core::ptr::read_volatile((va + PL011_CR) as *const u32);
            let lcrh = core::ptr::read_volatile((va + PL011_LCRH) as *const u32);
            core::ptr::write_volatile((va + PL011_CR) as *mut u32, cr & !CR_UARTEN);
            let mut n = 0u32;
            while n < 100_000 && (core::ptr::read_volatile((va + PL011_FR) as *const u32) & FR_BUSY) != 0 { n += 1; }
            core::ptr::write_volatile((va + PL011_IBRD) as *mut u32, ibrd);
            core::ptr::write_volatile((va + PL011_FBRD) as *mut u32, fbrd);
            let next_lcrh = (lcrh & (1 << 4)) | super::line_control_bits(parity, bits);
            core::ptr::write_volatile((va + PL011_LCRH) as *mut u32, next_lcrh);
            let flow_mask = (1 << 15) | (1 << 14);
            let next_cr = (cr & !flow_mask) | super::flow_control_bits(flow);
            core::ptr::write_volatile((va + PL011_CR) as *mut u32, next_cr);
        }
    }

    /// RX interrupt service: drain the FIFO empty, then re-check the masked
    /// interrupt status and drain again while it is still asserted. The RX and
    /// RX-timeout interrupts are cleared by emptying the FIFO, so nothing here
    /// writes the interrupt-clear register — doing that after a drain discards
    /// the indication for bytes that arrived during it, which silently wedges
    /// the input line (see `crate::rx`).
    /// # C: O(bytes pending)
    pub fn rx_isr() {
        let _ = rx_isr_claimed(super::deliver);
    }

    fn rx_isr_claimed(dlv: fn(u8)) -> bool {
        if !super::rx_enabled() { return false; }
        let va = base(); if va == 0 { return false; }
        // SAFETY: masked interrupt-status read through the published PL011 Device VA.
        if !unsafe { hal_aarch64::pl011::rx_irq_pending() } { return false; }
        let _ = crate::rx::service_rx(
            || {
                // SAFETY: FR/DR reads through the published PL011 Device VA.
                unsafe {
                    if (core::ptr::read_volatile((va + PL011_FR) as *const u32) & FR_RXFE) != 0 { return None; }
                    Some(core::ptr::read_volatile((va + PL011_DR) as *const u32) as u8)
                }
            },
            // SAFETY: masked interrupt-status read through the published PL011 Device VA.
            || unsafe { hal_aarch64::pl011::rx_irq_pending() },
            dlv,
        );
        true
    }

    fn rx_isr_irq(_irq: u32) -> arch_irq::IrqReport {
        arch_irq::IrqReport::hard(if rx_isr_claimed(super::deliver) {
            arch_irq::IrqRet::Handled
        } else {
            arch_irq::IrqRet::NotMine
        })
    }

    /// Detect the PL011 (boot-published base VA) + register the console
    /// TX/RX. `_dev_window_base` unused on arm (PL011 already device-mapped
    /// at boot). Returns true on detection.
    /// # SAFETY: PL011 Device VA published; single-CPU, IRQs masked.
    /// # C: O(1)
    pub(super) unsafe fn init(_bsp_apic: u8, _dev_window_base: u64,
        dlv: fn(&'static AtomicU64, u8)) -> bool {
        let va = hal_aarch64::pl011::base_va();
        if va == 0 { return false; }
        BASE.store(va, Ordering::Release);
        DELIVER.store(dlv as usize as u64, Ordering::Release);
        if arch_irq::request_arm_irq_line_handler(PL011_INTID, rx_isr_irq).is_err() {
            BASE.store(0, Ordering::Release);
            return false;
        }
        let (baud, parity, bits, flow) = super::configured_line();
        set_line(baud, parity, bits, flow);
        // SAFETY: GIC is up; PL011 owns SPI 33 and it is level-sensitive.
        unsafe { arch_irq::gic::enable_intid_level(PL011_INTID); }
        // SAFETY: PL011 was enabled by boot mapping and is now owned by this driver.
        unsafe { hal_aarch64::pl011::enable_rx_irq(); }
        RX_ENABLED.store(true, Ordering::Release);
        PRESENT.store(true, Ordering::Release);
        true
    }

    /// Clear the bound PL011 state. The boot mapping remains owned by the
    /// platform/early MMU setup; this driver stops publishing the UART as bound.
    /// # SAFETY: called by driver-core remove; no concurrent probe/remove.
    /// # C: O(1)
    pub(super) unsafe fn remove() {
        RX_ENABLED.store(false, Ordering::Release);
        // SAFETY: driver-core remove owns PL011 teardown.
        unsafe { hal_aarch64::pl011::disable_rx_irq(); }
        // SAFETY: PL011 owns SPI 33 while bound.
        unsafe { arch_irq::gic::disable_intid(PL011_INTID); }
        let _ = arch_irq::free_arm_irq_line_handler(PL011_INTID);
        BASE.store(0, Ordering::Release);
        PRESENT.store(false, Ordering::Release);
    }

    /// Stop PL011 RX interrupt delivery for terminal system shutdown while
    /// keeping the console TX path bound for late shutdown logging.
    /// # SAFETY: called by driver-core shutdown; no concurrent probe/remove.
    /// # C: O(1)
    pub(super) unsafe fn shutdown() {
        RX_ENABLED.store(false, Ordering::Release);
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
    pub unsafe fn console_to_polled() {}
    /// No PL011 on non-arm arches; baud no-op.
    /// # C: O(1)
    pub fn set_baud(_baud: u32) {}
    /// No PL011 on non-arm arches; line setup no-op.
    pub fn set_line(_baud: u32, _parity: u8, _bits: u8, _flow: bool) {}
    /// No PL011 on non-arm arches.
    /// # C: O(1)
    pub fn rx_isr() {}
    /// No PL011 on non-arm arches; detect fails.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn init(_bsp_apic: u8, _dev_window_base: u64,
        _dlv: fn(&'static core::sync::atomic::AtomicU64, u8)) -> bool { false }
    /// No PL011 on non-arm arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn remove() {}
    /// No PL011 on non-arm arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn shutdown() {}
}

pub use imp::{console_to_polled, emit, rx_isr, set_baud, set_line};

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
        // SAFETY: p was stored from this exact function-pointer type.
        let dlv: fn(&'static AtomicU64, u8) = unsafe { core::mem::transmute(p as usize) };
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

    fn pm(&self) -> Option<&'static drv::DevPmOps> { Some(&pm::PM_OPS) }

    fn shutdown(&self, _dev: &drv::Device) {
        // SAFETY: driver-core shutdown owns terminal platform-device quiesce.
        unsafe { imp::shutdown(); }
    }
}

/// Driver-model handle; name "pl011-serial" matches the platform/serial0
/// device kmain registers. Exposed so `drv-serial::init` registers the
/// per-arch UART driver uniformly.
pub static UART_DRIVER: &dyn drv::Driver = &UartPl011Drv;

#[cfg(test)]
mod tests {
    use super::{flow_control_bits, line_control_bits, pl011_divisor, UARTCLK_HZ};

    #[test]
    fn console_line_options_encode_data_bits_and_parity() {
        assert_eq!(line_control_bits(b'n', 8), 0x03 << 5);
        assert_eq!(line_control_bits(b'o', 7), (0x02 << 5) | (1 << 1));
        assert_eq!(line_control_bits(b'e', 7), (0x02 << 5) | (1 << 1) | (1 << 2));
    }

    #[test]
    fn console_hardware_flow_enables_cts_and_rts() {
        assert_eq!(flow_control_bits(false), 0);
        assert_eq!(flow_control_bits(true), (1 << 15) | (1 << 14));
    }

    // Reference divisors for the standard qemu-virt 24 MHz UARTCLK, cross-checked
    // against Linux `pl011_calc_divisor` (div = round(uartclk*4/baud); ibrd=div>>6,
    // fbrd=div&63). 115200 → 13.0208 → IBRD=13, FBRD=1 is the canonical PL011 value.
    #[test]
    fn divisor_24mhz_reference_rates() {
        assert_eq!(pl011_divisor(UARTCLK_HZ, 115200), (13, 1));
        assert_eq!(pl011_divisor(UARTCLK_HZ, 38400),  (39, 4));
        assert_eq!(pl011_divisor(UARTCLK_HZ, 9600),   (156, 16));
    }

    // B0 / unset speed → (0,0); the driver treats that as "leave current rate".
    #[test]
    fn divisor_zero_baud_is_noop_sentinel() {
        assert_eq!(pl011_divisor(UARTCLK_HZ, 0), (0, 0));
    }

    // The 6.6 fixed-point round-trip: reconstructed rate is within the PL011's
    // representable granularity of the requested rate (no gross divisor error).
    #[test]
    fn divisor_reconstructs_close_to_requested() {
        for &baud in &[9600u32, 19200, 38400, 57600, 115200, 230400] {
            let (ibrd, fbrd) = pl011_divisor(UARTCLK_HZ, baud);
            let div64 = (ibrd * 64 + fbrd) as u64; // 6.6 fixed point × 64
            let got = (UARTCLK_HZ as u64 * 4) / div64; // baud = uartclk*4/div64
            let err = if got > baud as u64 { got - baud as u64 } else { baud as u64 - got };
            assert!(err * 1000 < baud as u64 * 5, "baud {baud}: err {err} > 0.5%");
        }
    }
}
