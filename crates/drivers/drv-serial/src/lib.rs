#![no_std]
//! 8250 (x86_64 COM1 / SPCR I/O) + PL011 (aarch64) UART console driver.
//!
//! Linux-compliant detection: the UART is **probed**, never assumed. The
//! firmware-elected console (ACPI SPCR, via `firmware::spcr_*`) wins; on
//! x86 with no SPCR we fall back to the legacy 8250 scratch-register
//! probe at COM1. A machine with no serial port simply has no serial
//! console — the framebuffer/VT console (registered elsewhere) stands.
//!
//! On detection the driver exposes `emit` (TX) — the kernel registers
//! it as the klog console sink under debug-boot (R06) — and drains RX into
//! the tty line discipline via a kernel-installed sink hook (so this crate
//! has no tty/klog dependency), plus IRQ4 routing on x86. docs/35§3 (one
//! `drv-*` crate per device), docs/53 (kernel = glue).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// RX byte sink — the tty line discipline (`push_and_wake_fg`). Wired by
/// the kernel; keeps this crate free of any tty dependency.
static RX_SINK: AtomicU64 = AtomicU64::new(0);
/// Detected UART base: x86 I/O port (addr_space=IO) or MMIO VA (PL011).
static BASE: AtomicU64 = AtomicU64::new(0);
static PRESENT: AtomicBool = AtomicBool::new(false);

/// Install the RX byte sink. Call once at boot before `init`.
/// # C: O(1)
pub fn set_rx_sink(f: fn(u8)) { RX_SINK.store(f as usize as u64, Ordering::Release); }

#[inline]
fn deliver(b: u8) {
    let p = RX_SINK.load(Ordering::Acquire);
    if p == 0 { return; }
    // SAFETY: p was stored from a `fn(u8)` by set_rx_sink; transmute back to that type.
    let f: fn(u8) = unsafe { core::mem::transmute(p as usize) };
    f(b);
}

/// True once a UART has been detected + registered by `init`.
/// # C: O(1)
pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

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

    /// Console TX: write each byte once THR is empty. Exposed for the
    /// kernel to register as the klog byte sink (under debug-boot).
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

    /// Timer-tick fallback RX poll.
    /// # SAFETY: port I/O at CPL=0; single-CPU.
    /// # C: O(1)
    pub unsafe fn poll() {
        let b = base(); if b == 0 { return; }
        // SAFETY: LSR read at the detected COM base.
        if unsafe { inb(b + LSR) } & 0x01 == 0 { return; }
        // SAFETY: LSR.DR set ⇒ RBR has a byte.
        let c = unsafe { inb(b + RBR) };
        deliver(c);
    }

    /// COM RX interrupt handler — drains the FIFO into the sink.
    /// # C: O(bytes pending)
    pub fn rx_isr() {
        let b = base(); if b == 0 { return; }
        let mut n = 0;
        while n < 64 {
            // SAFETY: LSR read at the detected COM base.
            if unsafe { inb(b + LSR) } & 0x01 == 0 { break; }
            // SAFETY: LSR.DR set ⇒ RBR has a byte.
            let c = unsafe { inb(b + RBR) };
            deliver(c);
            n += 1;
        }
    }

    /// Detect + register the serial console (TX sink + RX IRQ4). No-op
    /// when no UART responds. `dev_window_base` is the kernel device-MMIO
    /// window (for the I/O APIC map). Returns true if serial was found.
    /// # SAFETY: post-ACPI + post-LAPIC-enable + MmuOps live; single-CPU,
    /// IRQs masked. Maps the I/O APIC, programs IRQ4, port I/O to the UART.
    /// # C: O(1)
    pub unsafe fn init(bsp_apic: u8, dev_window_base: u64) -> bool {
        // SAFETY: detection does only harmless scratch round-trips.
        let port = match unsafe { detect() } { Some(p) => p, None => return false };
        BASE.store(port as u64, Ordering::Release);
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
                let _ = arch_irq::register_msi_handler(vec, rx_isr);
                let ovr = firmware::irq4_flags();
                let pin = firmware::irq4_gsi().wrapping_sub(firmware::ioapic_gsi_base());
                let active_low = (ovr & 0x3) == 3;
                let level = ((ovr >> 2) & 0x3) == 3;
                // SAFETY: I/O APIC mapped; vec has a handler; single-CPU pre-init.
                unsafe { hal_x86_64::ioapic::program_redirect(pin, vec, bsp_apic, level, active_low); }
                // Unmask UART RX-data-available (IER bit0).
                // SAFETY: IER write at CPL=0 to the detected COM base.
                unsafe { outb(port + IER, 0x01); }
            }
        }
        true
    }
}

// ---------------------------------------------------------------- aarch64

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::*;
    const PL011_DR: u64 = 0x00;
    const PL011_FR: u64 = 0x18;
    const FR_RXFE:  u32 = 1 << 4;
    const FR_TXFF:  u32 = 1 << 5;

    fn base() -> u64 { BASE.load(Ordering::Acquire) }

    /// Console TX over PL011. Exposed for the kernel to register as the
    /// klog byte sink (under debug-boot).
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

    /// # SAFETY: reads through the published PL011 Device VA; single-CPU.
    /// # C: O(N_bytes_drained)
    pub unsafe fn poll() {
        let va = base(); if va == 0 { return; }
        let mut n = 0;
        while n < 16 {
            // SAFETY: FR read through the PL011 Device VA.
            let fr = unsafe { core::ptr::read_volatile((va + PL011_FR) as *const u32) };
            if (fr & FR_RXFE) != 0 { break; }
            // SAFETY: DR read through the PL011 Device VA.
            let b = unsafe { core::ptr::read_volatile((va + PL011_DR) as *const u32) } as u8;
            deliver(b);
            n += 1;
        }
    }

    /// arm RX is timer-tick polled; MSI/SPI-driven RX is a follow-up.
    /// # C: O(1)
    pub fn rx_isr() {}

    /// Detect the PL011 (SPCR MMIO, else the boot-published base) + register
    /// the console TX. RX is timer-tick polled. `_dev_window_base` unused on
    /// arm (PL011 already device-mapped at boot).
    /// # SAFETY: PL011 Device VA published; single-CPU, IRQs masked.
    /// # C: O(1)
    pub unsafe fn init(_bsp_apic: u8, _dev_window_base: u64) -> bool {
        let va = hal_aarch64::pl011::base_va();
        if va == 0 { return false; }
        BASE.store(va, Ordering::Release);
        PRESENT.store(true, Ordering::Release);
        true
    }
}

pub use imp::{emit, init, poll, rx_isr};
