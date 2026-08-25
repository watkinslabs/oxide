//! x86_64 16550 hardware backend.


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
use super::pm::{FCR_ENABLE, FCR_RX_TRIGGER_8};
const FCR_CLEAR_RX: u8 = 0x02;
const FCR_CLEAR_TX: u8 = 0x04;
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

/// Apply the complete runtime-console line setup after probe. # C: O(1)
pub fn set_line(baud: u32, parity: u8, bits: u8, flow: bool) {
    let b = base();
    if b == 0 || baud == 0 { return; }
    let divisor = (115_200 / baud).clamp(1, 0xFFFF) as u16;
    let _port = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
    // SAFETY: one serialized DLAB/LCR/MCR transaction on the detected UART.
    unsafe {
        let old_lcr = inb(b + LCR);
        outb(b + LCR, old_lcr | 0x80);
        outb(b + RBR, divisor as u8);
        outb(b + IER, (divisor >> 8) as u8);
        outb(b + LCR, super::line_control_bits(parity, bits));
        let mcr = inb(b + MCR);
        outb(b + MCR, (mcr & !(1 << 5)) | super::modem_control_bits(flow));
    }
}

/// COM interrupt handler. Each IIR pass services receive before transmit,
/// fills at most one hardware FIFO, and calls tty delivery only after
/// dropping the aliased-register lock. As Linux serial8250 does for an ISA
/// IRQ chain, passes continue until the edge-triggered line deasserts.
/// # C: O(IRQ_PASS_LIMIT * (RX bytes + one 16-byte TX FIFO load))
pub fn rx_isr() {
    let _ = service_irq_chain(super::deliver);
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
pub(super) unsafe fn init(bsp_apic: u8, dev_window_base: u64,
    dlv: fn(&'static AtomicU64, u8)) -> bool {
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
    let (baud, parity, bits, flow) = super::configured_line();
    set_line(baud, parity, bits, flow);
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
            if !unsafe { arch_irq::program_x86_ioapic(pin, vec, u32::from(bsp_apic), level, active_low) } {
                let _ = arch_irq::free_x86_vector(vec);
                BASE.store(0, Ordering::Release);
                PRESENT.store(false, Ordering::Release);
                return false;
            }
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

/// Take the console off the interrupt-driven transmit queue and put it on
/// the synchronous one, flushing whatever the queue already holds.
///
/// The queue is drained by the transmit-empty INTERRUPT. A caller that is
/// about to silence every interrupt source — a panic, the stop before a
/// relocation — leaves every byte written after that point sitting in a
/// ring nothing will ever drain, which is a console that goes quiet at
/// exactly the moment its output is the only thing left. Observed: a crash
/// boot whose log stopped mid-word after the interrupt controller was
/// cleared, on a machine that was still running.
///
/// Idempotent, and safe to call with interrupts already masked: everything
/// after the switch is a polled write.
/// # SAFETY: writes the port's IER and data registers at CPL 0.
/// # C: O(queued bytes * bounded THRE polls)
pub unsafe fn console_to_polled() {
    let port = BASE.load(Ordering::Acquire) as u16;
    if port == 0 { return; }
    let mut state = PORT.lock_irqsave::<hal_x86_64::X86IrqGate>();
    if !state.runtime() { return; }
    state.stop_runtime();
    // SAFETY: the port lock owns the IER shadow/register pair.
    unsafe { outb(port + IER, state.ier()); }
    while let Some(byte) = state.pop_for_poll() { poll_byte(port, byte); }
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
