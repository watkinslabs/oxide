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
#[cfg(target_arch = "x86_64")]
static IRQ_VEC: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static IRQ_PIN: AtomicU64 = AtomicU64::new(u64::MAX);
/// tty-delivery callback (`fn(u8)`), stored from `init`'s parameter so
/// the bare-`fn()` MSI handler trampoline can reach it without args.
static DELIVER: AtomicU64 = AtomicU64::new(0);

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
pub fn configure_probe(bsp_apic: u8, dev_window_base: u64, dlv: fn(u8)) {
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
    // SAFETY: p was stored from a `fn(u8)` by init's deliver param; transmute back to that exact type.
    let f: fn(u8) = unsafe { core::mem::transmute(p as usize) };
    f(b);
}

// ---------------------------------------------------------------- x86_64
#[cfg(target_arch = "x86_64")]
mod imp {
    use super::*;

    /// # SAFETY: privileged port I/O legal at CPL=0.
    #[inline]
    unsafe fn inb(port: u16) -> u8 {
        let v: u8;
        // SAFETY: `in` at CPL=0; no memory effect on the caller's state.
        unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)); }
        v
    }
    /// # SAFETY: privileged port I/O legal at CPL=0.
    #[inline]
    unsafe fn outb(port: u16, v: u8) {
        // SAFETY: `out` at CPL=0; no memory effect on the caller's state.
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)); }
    }

    // 8250 register offsets from the port base.
    const RBR: u16 = 0; // THR on write
    const IER: u16 = 1;
    const IIR: u16 = 2; // FCR on write
    const FCR: u16 = 2;
    const LCR: u16 = 3; // line control; bit7 = DLAB (selects DLL/DLM at base+0/+1)
    const MCR: u16 = 4;
    const LSR: u16 = 5; // bit0 = RX data ready, bit5 = THR empty
    const SCR: u16 = 7; // scratch
    const FCR_ENABLE: u8 = 0x01;
    const FCR_CLEAR_RX: u8 = 0x02;
    const FCR_CLEAR_TX: u8 = 0x04;
    const FCR_RX_TRIGGER_8: u8 = 0x80;
    const IIR_NO_INTERRUPT: u8 = 1 << 0;
    const LSR_DATA_READY: u8 = 1 << 0;
    const LSR_THR_EMPTY: u8 = 1 << 5;

    /// Steady 16550 FIFO configuration after the startup clear. # C: O(1)
    pub(super) const fn fifo_mode() -> u8 { FCR_ENABLE | FCR_RX_TRIGGER_8 }

    /// Legacy 8250 detection: round-trip a sentinel through the scratch
    /// register. A responding UART returns it; empty I/O space reads 0xFF.
    /// # SAFETY: port I/O at CPL=0 to a candidate COM port (no side effects).
    unsafe fn scratch_probe(base: u16) -> bool {
        // SAFETY: SCR is a RW scratch byte; round-trip has no device side effect.
        unsafe { outb(base + SCR, 0xAE); inb(base + SCR) == 0xAE }
    }

    /// Detect the console UART I/O base. SPCR-elected I/O port wins; else
    /// legacy-probe COM1 (0x3F8). Returns the port, or None.
    /// # SAFETY: port I/O at CPL=0.
    unsafe fn detect() -> Option<u16> {
        if firmware::spcr_present() && firmware::spcr_addr_space() == 1 {
            let p = firmware::spcr_base() as u16;
            // SAFETY: SPCR-named port; scratch test confirms a live UART.
            if p != 0 && unsafe { scratch_probe(p) } { return Some(p); }
        }
        // SAFETY: legacy COM1 probe; harmless scratch round-trip.
        if unsafe { scratch_probe(0x3F8) } { return Some(0x3F8); }
        None
    }

    fn base() -> u16 { BASE.load(Ordering::Acquire) as u16 }

    /// Poll one byte out through THR. This is the early/late console fallback,
    /// used only while the runtime IRQ engine is unavailable or quiesced.
    /// PORT must be held. # C: O(spins)
    fn poll_byte(base: u16, byte: u8) {
        let mut n = 0u32;
        // SAFETY: LSR port read at CPL=0 to the detected COM base.
        while n < 100_000 && unsafe { inb(base + LSR) } & LSR_THR_EMPTY == 0 { n += 1; }
        // SAFETY: THR write at CPL=0 to the detected COM base.
        unsafe { outb(base + RBR, byte); }
    }

    /// Runtime TX follows Linux serial core: copy into the xmit ring, arm the
    /// TX-empty interrupt once, and return. The ISR fills the 16-byte hardware
    /// FIFO without per-byte readiness polls. Early boot and shutdown retain
    /// the synchronous fallback because interrupts cannot make progress there.
    /// # C: O(len(bytes)) memory copies; O(1) port I/O
    pub fn emit(bytes: &[u8]) {
        let b = base();
        if b == 0 { return; }
        let mut port = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
        if port.runtime() {
            let transition = port.enqueue(bytes);
            if transition.ier_changed {
                // SAFETY: the port lock owns the IER shadow/register pair.
                unsafe { outb(b + IER, port.ier()); }
            }
            return;
        }
        for &byte in bytes {
            poll_byte(b, byte);
        }
    }

    /// Reprogram the line baud (TCSETS `c_ospeed`). Standard PC 16550 base
    /// clock is 1.8432 MHz, so the 16-bit divisor = 115200 / baud. Toggle DLAB
    /// to expose the divisor latch (DLL @ base+0, DLM @ base+1), write it, then
    /// restore the line-control byte. # C: O(1) port I/O
    pub fn set_baud(baud: u32) {
        let b = base();
        if b == 0 || baud == 0 { return; }
        let divisor = (115_200 / baud).clamp(1, 0xFFFF) as u16;
        let _port = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
        // SAFETY: DLAB toggle + divisor-latch writes at CPL=0 to the detected
        // COM base; DLL/DLM alias base+0/+1 only while DLAB=1, restored after.
        unsafe {
            let lcr = inb(b + LCR);
            outb(b + LCR, lcr | 0x80);            // DLAB=1
            outb(b + RBR, (divisor & 0xff) as u8);  // DLL
            outb(b + IER, (divisor >> 8) as u8);    // DLM
            outb(b + LCR, lcr & !0x80);           // DLAB=0: restore data regs + line ctl
        }
    }

    /// COM interrupt handler. Each IIR pass services receive before transmit,
    /// fills at most one hardware FIFO, and calls tty delivery only after
    /// dropping the aliased-register lock. As Linux serial8250 does for an ISA
    /// IRQ chain, passes continue until the edge-triggered line deasserts.
    /// # C: O(IRQ_PASS_LIMIT * (RX bytes + one 16-byte TX FIFO load))
    pub fn rx_isr(dlv: fn(u8)) {
        let _ = service_irq_chain(dlv);
    }

    fn rx_isr_claimed(dlv: fn(u8)) -> bool {
        let b = base(); if b == 0 { return false; }
        // SAFETY: IIR read at the detected COM base; bit 0 means this shared ISA line is not ours.
        if unsafe { inb(b + IIR) } & IIR_NO_INTERRUPT != 0 { return false; }
        let mut received = [0u8; 64];
        let mut rx_count = 0usize;
        {
            let mut port = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
            // SAFETY: LSR read at the detected COM base.
            let mut status = unsafe { inb(b + LSR) };
            if super::rx_enabled() {
                while rx_count < received.len() && status & LSR_DATA_READY != 0 {
                    // SAFETY: LSR.DR set means RBR contains one received byte.
                    received[rx_count] = unsafe { inb(b + RBR) };
                    rx_count += 1;
                    // SAFETY: re-sample the same detected UART's line status.
                    status = unsafe { inb(b + LSR) };
                }
            }
            if status & LSR_THR_EMPTY != 0 && port.ier() & tx::IER_TX_EMPTY != 0 {
                let mut fifo = [0u8; tx::TX_FIFO_DEPTH];
                let transition = port.take_fifo(&mut fifo);
                for &byte in &fifo[..transition.count] {
                    // SAFETY: one THRE service may fill the enabled 16-byte FIFO.
                    unsafe { outb(b + RBR, byte); }
                }
                if transition.ier_changed {
                    // SAFETY: the port lock owns the IER shadow/register pair.
                    unsafe { outb(b + IER, port.ier()); }
                }
            }
        }
        for &byte in &received[..rx_count] {
            dlv(byte);
        }
        true
    }

    fn service_irq_chain(dlv: fn(u8)) -> bool {
        tx::service_irq_chain(|| rx_isr_claimed(dlv))
    }

    /// I/O APIC line-handler adapter: drains IIR until the ISA line deasserts,
    /// reports whether this UART claimed it, and pulls `deliver` from static.
    /// # C: O(IRQ_PASS_LIMIT * bytes pending per pass)
    fn uart_isr_line(_irq: u32) -> arch_irq::IrqReport {
        arch_irq::IrqReport::hard(if service_irq_chain(super::deliver) {
            arch_irq::IrqRet::Handled
        } else {
            arch_irq::IrqRet::NotMine
        })
    }

    /// Detect + register the serial console (TX sink + RX IRQ4). No-op
    /// when no UART responds. `dev_window_base` is the kernel device-MMIO
    /// window (for the I/O APIC map). `dlv` is the tty-delivery callback,
    /// stored for the IRQ trampoline. Returns true on detect.
    /// # SAFETY: post-ACPI + post-LAPIC-enable + MmuOps live; single-CPU,
    /// IRQs masked. Maps the I/O APIC, programs IRQ4, port I/O to the UART.
    /// # C: O(1)
    pub(super) unsafe fn init(bsp_apic: u8, dev_window_base: u64, dlv: fn(u8)) -> bool {
        // SAFETY: detection does only harmless scratch round-trips.
        let port = match unsafe { detect() } { Some(p) => p, None => return false };
        BASE.store(port as u64, Ordering::Release);
        DELIVER.store(dlv as usize as u64, Ordering::Release);
        PRESENT.store(true, Ordering::Release);
        RX_ENABLED.store(false, Ordering::Release);
        {
            let mut state = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
            state.stop_runtime();
            state.discard();
        }
        // Clear stale hardware state, then enable the FIFO with the standard
        // eight-byte receive trigger before exposing RX interrupts.
        // SAFETY: detected 16550 port, single-CPU probe before its IRQ is enabled.
        unsafe {
            outb(port + IER, 0);
            outb(port + FCR, FCR_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX);
            outb(port + FCR, fifo_mode());
            let mcr = inb(port + MCR);
            outb(port + MCR, tx::irq_mcr(mcr));
        }
        // Route IRQ4 → an RX-drain vector via the I/O APIC, if present.
        use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
        let ioapic_pa = firmware::ioapic_pa();
        if ioapic_pa != 0 {
            let va = dev_window_base | (ioapic_pa & 0xffff_ffff);
            let pf = PageFlags::READ | PageFlags::WRITE | PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH;
            // SAFETY: device-window VA disjoint from RAM; ioapic_pa is the MADT base; single-CPU pre-init.
            unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::map(Va(va), Pa(ioapic_pa), pf, PageSize::P4K); }
            hal_x86_64::ioapic::set_base_va(va);
            if let Some(vec) = arch_irq::alloc_x86_vector() {
                if arch_irq::register_irq_line_handler(vec as u32, uart_isr_line).is_err() {
                    let _ = arch_irq::free_x86_vector(vec);
                    BASE.store(0, Ordering::Release);
                    PRESENT.store(false, Ordering::Release);
                    return false;
                }
                let ovr = firmware::legacy_irq_flags(4).unwrap_or(0);
                let gsi = firmware::legacy_irq_gsi(4).unwrap_or(4);
                let pin = gsi.wrapping_sub(firmware::ioapic_gsi_base());
                let active_low = (ovr & 0x3) == 3;
                let level = ((ovr >> 2) & 0x3) == 3;
                // SAFETY: I/O APIC mapped; vec has a handler; single-CPU pre-init.
                unsafe { hal_x86_64::ioapic::program_redirect(pin, vec, bsp_apic, level, active_low); }
                IRQ_VEC.store(vec as u64, Ordering::Release);
                IRQ_PIN.store(pin as u64, Ordering::Release);
                let mut state = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
                state.start_runtime();
                // SAFETY: the port lock owns the IER shadow/register pair.
                unsafe { outb(port + IER, state.ier()); }
                RX_ENABLED.store(true, Ordering::Release);
            }
        }
        true
    }

    /// Tear down the UART RX interrupt and clear the detected singleton state.
    /// # SAFETY: called by driver-core remove; no concurrent probe/remove.
    /// # C: O(1)
    pub(super) unsafe fn remove() {
        RX_ENABLED.store(false, Ordering::Release);
        let port = BASE.load(Ordering::Acquire) as u16;
        if port != 0 {
            let mut state = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
            state.stop_runtime();
            state.discard();
            // SAFETY: the port lock owns the IER shadow/register pair.
            unsafe { outb(port + IER, state.ier()); }
        }
        let pin = IRQ_PIN.swap(u64::MAX, Ordering::AcqRel);
        if pin != u64::MAX {
            // SAFETY: I/O APIC mapping was installed before IRQ_PIN was published.
            unsafe { hal_x86_64::ioapic::mask(pin as u32); }
        }
        let vec = IRQ_VEC.swap(0, Ordering::AcqRel);
        if vec != 0 {
            let _ = arch_irq::free_x86_vector(vec as u8);
        }
        BASE.store(0, Ordering::Release);
        PRESENT.store(false, Ordering::Release);
    }

    /// Stop UART RX interrupt delivery for terminal system shutdown while
    /// keeping the console TX path bound for late shutdown logging.
    /// # SAFETY: called by driver-core shutdown; no concurrent probe/remove.
    /// # C: O(pending TX bytes * bounded THRE polls)
    pub(super) unsafe fn shutdown() {
        RX_ENABLED.store(false, Ordering::Release);
        let port = BASE.load(Ordering::Acquire) as u16;
        if port != 0 {
            let mut state = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
            state.stop_runtime();
            // SAFETY: the port lock owns the IER shadow/register pair.
            unsafe { outb(port + IER, state.ier()); }
            while let Some(byte) = state.pop_for_poll() {
                poll_byte(port, byte);
            }
        }
        let pin = IRQ_PIN.load(Ordering::Acquire);
        if pin != u64::MAX {
            // SAFETY: I/O APIC mapping was installed before IRQ_PIN was published.
            unsafe { hal_x86_64::ioapic::mask(pin as u32); }
        }
    }
}

// --------------------------------------------------------- empty shell
#[cfg(not(target_arch = "x86_64"))]
mod imp {
    /// No 16550 on non-x86 arches; TX no-op.
    /// # C: O(1)
    pub fn emit(_bytes: &[u8]) {}
    /// No 16550 on non-x86 arches; baud no-op.
    /// # C: O(1)
    pub fn set_baud(_baud: u32) {}
    /// No 16550 on non-x86 arches.
    /// # C: O(1)
    pub fn rx_isr(_dlv: fn(u8)) {}
    /// No 16550 on non-x86 arches; detect fails.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn init(_bsp_apic: u8, _dev_window_base: u64, _dlv: fn(u8)) -> bool { false }
    /// No 16550 on non-x86 arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn remove() {}
    /// No 16550 on non-x86 arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub(super) unsafe fn shutdown() {}
}

pub use imp::{emit, rx_isr, set_baud};

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
        // SAFETY: p was stored from a `fn(u8)` by configure_probe.
        let dlv: fn(u8) = unsafe { core::mem::transmute(p as usize) };
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
mod tests {
    use super::imp::fifo_mode;

    #[test]
    fn steady_fifo_mode_keeps_fifo_enabled_with_eight_byte_rx_trigger() {
        assert_eq!(fifo_mode(), 0x81);
    }
}
