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

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Detected COM I/O base (x86 port). 0 ⇒ no UART bound.
static BASE: AtomicU64 = AtomicU64::new(0);
static PRESENT: AtomicBool = AtomicBool::new(false);
static BSP_APIC: AtomicU64 = AtomicU64::new(0);
static DEV_WINDOW_BASE: AtomicU64 = AtomicU64::new(0);
static IRQ_VEC: AtomicU64 = AtomicU64::new(0);
static IRQ_PIN: AtomicU64 = AtomicU64::new(u64::MAX);
/// tty-delivery callback (`fn(u8)`), stored from `init`'s parameter so
/// the bare-`fn()` MSI handler trampoline can reach it without args.
static DELIVER: AtomicU64 = AtomicU64::new(0);

/// True once a 16550 UART has been detected + registered by `init`.
/// # C: O(1)
pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

/// Install boot-probe parameters used when the drv core calls
/// `Uart16550Drv::probe`.
/// # C: O(1)
pub fn configure_probe(bsp_apic: u8, dev_window_base: u64, dlv: fn(u8)) {
    BSP_APIC.store(bsp_apic as u64, Ordering::Release);
    DEV_WINDOW_BASE.store(dev_window_base, Ordering::Release);
    DELIVER.store(dlv as usize as u64, Ordering::Release);
}

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
    const LSR: u16 = 5; // bit0 = RX data ready, bit5 = THR empty
    const SCR: u16 = 7; // scratch

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

    /// Console TX: write each byte once THR is empty.
    /// # C: O(len(bytes))
    pub fn emit(bytes: &[u8]) {
        let b = base();
        if b == 0 { return; }
        for &c in bytes {
            let mut n = 0u32;
            // SAFETY: LSR port read at CPL=0 to the detected COM base.
            while n < 100_000 && unsafe { inb(b + LSR) } & 0x20 == 0 { n += 1; }
            // SAFETY: THR write at CPL=0 to the detected COM base.
            unsafe { outb(b + RBR, c); }
        }
    }

    /// Bounded RX poll for explicit diagnostics. Runtime RX uses IRQ4.
    /// # SAFETY: port I/O at CPL=0; single-CPU.
    /// # C: O(1)
    pub unsafe fn rx_poll(dlv: fn(u8)) {
        let b = base(); if b == 0 { return; }
        // SAFETY: LSR read at the detected COM base.
        if unsafe { inb(b + LSR) } & 0x01 == 0 { return; }
        // SAFETY: LSR.DR set ⇒ RBR has a byte.
        let c = unsafe { inb(b + RBR) };
        dlv(c);
    }

    /// COM RX interrupt handler — drains the FIFO into `dlv`.
    /// # C: O(bytes pending)
    pub fn rx_isr(dlv: fn(u8)) {
        let b = base(); if b == 0 { return; }
        let mut n = 0;
        while n < 64 {
            // SAFETY: LSR read at the detected COM base.
            if unsafe { inb(b + LSR) } & 0x01 == 0 { break; }
            // SAFETY: LSR.DR set ⇒ RBR has a byte.
            let c = unsafe { inb(b + RBR) };
            dlv(c);
            n += 1;
        }
    }

    /// Bare-`fn()` MSI handler trampoline: the I/O APIC vector handler
    /// signature has no args, so it pulls `deliver` from the stored
    /// static and drains the FIFO into it.
    /// # C: O(bytes pending)
    fn rx_isr_msi() { rx_isr(super::deliver); }

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
                if arch_irq::register_msi_handler(vec, rx_isr_msi).is_err() {
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
                // Unmask UART RX-data-available (IER bit0).
                // SAFETY: IER write at CPL=0 to the detected COM base.
                unsafe { outb(port + IER, 0x01); }
            }
        }
        true
    }

    /// Tear down the UART RX interrupt and clear the detected singleton state.
    /// # SAFETY: called by driver-core remove; no concurrent probe/remove.
    /// # C: O(1)
    pub(super) unsafe fn remove() {
        let port = BASE.load(Ordering::Acquire) as u16;
        if port != 0 {
            // SAFETY: IER write at CPL=0 to the detected COM base disables RX interrupts.
            unsafe { outb(port + IER, 0x00); }
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
}

// --------------------------------------------------------- empty shell
#[cfg(not(target_arch = "x86_64"))]
mod imp {
    /// No 16550 on non-x86 arches; TX no-op.
    /// # C: O(1)
    pub fn emit(_bytes: &[u8]) {}
    /// No 16550 on non-x86 arches.
    /// # SAFETY: shell; no side effects.
    /// # C: O(1)
    pub unsafe fn rx_poll(_dlv: fn(u8)) {}
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
}

pub use imp::{emit, rx_isr, rx_poll};

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
}

/// Driver-model handle; name "8250-serial" matches the platform/serial0
/// device kmain registers. Exposed so `drv-serial::init` registers the
/// per-arch UART driver uniformly.
pub static UART_DRIVER: &dyn drv::Driver = &Uart16550Drv;
