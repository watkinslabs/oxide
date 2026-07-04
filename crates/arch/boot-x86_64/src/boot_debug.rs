#[cfg(feature = "debug-boot")]
use klog::Uart;
#[cfg(feature = "debug-boot")]
use sync::{Spinlock, Tty as UartClass};
#[cfg(feature = "debug-boot")]
use crate::uart::{Uart16550, COM1};

// ---------------------------------------------------------------------------
// Boot-time UART sink for klog. Single instance behind `Spinlock` so the
// `klog::LogSink` thunk can drive it without `static mut` (`07§5`).
// ---------------------------------------------------------------------------

#[cfg(feature = "debug-boot")]
static BOOT_UART: Spinlock<Uart16550, UartClass>
    = Spinlock::new(Uart16550::new(COM1));

/// Initialise the boot UART before installing it as the klog sink.
/// # SAFETY: boot-only, single-CPU, before any concurrent UART user exists.
#[cfg(feature = "debug-boot")]
pub(crate) unsafe fn init_boot_uart() {
    // SAFETY: caller guarantees boot-only, single-CPU ownership of COM1.
    unsafe { BOOT_UART.lock().init(); }
}

/// klog `LogSink` adapter — drives `BOOT_UART` for every byte slice
/// klog emits. Registered via `klog::set_byte_sink` from
/// `_start_rust` after `BOOT_UART::init()`.
///
/// Uses `lock_irqsave` per `06§3.1` because klog can be called from
/// IRQ context (timer ISR's `tick_poll_uart`, fault handlers, panic
/// path). A plain `lock()` would deadlock if a kernel-mode klog
/// holder were preempted by an IRQ that itself klogs.
/// # C: O(len)
#[cfg(feature = "debug-boot")]
pub(crate) fn boot_emit(bytes: &[u8]) {
    let mut g = BOOT_UART.lock_irqsave::<hal_x86_64::X86IrqGate>();
    g.write_bytes(bytes);
}

/// klog clock thunk — surfaces `X86TimerOps::monotonic_ns` as the
/// `klog::ClockFn` after `set_tsc_khz` calibration.
/// # C: O(1)
pub(crate) fn now_ns_x86() -> u64 {
    use hal::TimerOps;
    hal_x86_64::X86TimerOps::monotonic_ns().0
}

/// Remap the legacy 8259A PIC pair to vectors 0x20–0x2F and mask every
/// line. The kernel routes interrupts through the LAPIC/IOAPIC, so the
/// 8259 must not deliver: its default IRQ0–7 land on vectors 0x08–0x0F
/// which alias the CPU exception vectors (0x08 = #DF). A bootloader
/// that leaves the PIC live + a free-running PIT then vectors a timer
/// tick into the double-fault handler at the first `sti`. Linux does
/// the same ICW1–4 remap + mask before switching to the APIC.
///
/// # SAFETY: boot-only, single-CPU, IRQs masked; ports 0x20/0x21/
/// 0xA0/0xA1 are the always-present legacy PIC registers on the q35
/// target. # C: O(1) # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn remap_and_mask_pic() {
    // # SAFETY: single byte `out` to a legacy PIC port; no memory effect.
    unsafe fn outb(port: u16, val: u8) {
        // SAFETY: port-mapped I/O to the legacy 8259 PIC during single-CPU boot with IRQs masked; the q35 machine always wires these ports.
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags)); }
    }
    // SAFETY: ICW1-4 init the PIC pair, ICW2 sets vector bases 0x20
    // (master) / 0x28 (slave) away from exceptions, then 0xFF masks
    // every line. All writes are to the always-present legacy ports.
    unsafe {
        outb(0x20, 0x11); // master ICW1: init + ICW4 to follow
        outb(0xA0, 0x11); // slave  ICW1
        outb(0x21, 0x20); // master ICW2: IRQ0-7 -> 0x20-0x27
        outb(0xA1, 0x28); // slave  ICW2: IRQ8-15 -> 0x28-0x2F
        outb(0x21, 0x04); // master ICW3: slave on IRQ2
        outb(0xA1, 0x02); // slave  ICW3: cascade identity
        outb(0x21, 0x01); // master ICW4: 8086 mode
        outb(0xA1, 0x01); // slave  ICW4
        outb(0x21, 0xFF); // mask all master IRQs
        outb(0xA1, 0xFF); // mask all slave IRQs
    }
}

/// Boot-time CPU identification log. Reads CPUID leaves 0 (vendor)
/// and 0x80000002..0x80000004 (brand) and emits both via klog.
/// # C: O(1)
#[cfg(feature = "debug-boot")]
pub(crate) fn log_cpu_info() {
    let v = hal_x86_64::cpuid_vendor();
    klog::write_raw(b"[INFO]  cpu vendor: ");
    klog::write_raw(&v);
    let b = hal_x86_64::cpuid_brand();
    let brand_len = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    klog::write_raw(b"\n[INFO]  cpu brand: ");
    klog::write_raw(&b[..brand_len]);
    klog::write_raw(b"\n[INFO]  mmu cr0=");
    klog::write_hex_u64(hal_x86_64::read_cr0());
    klog::write_raw(b" cr3=");
    klog::write_hex_u64(hal_x86_64::read_cr3());
    klog::write_raw(b" cr4=");
    klog::write_hex_u64(hal_x86_64::read_cr4());
    klog::write_raw(b" efer=");
    klog::write_hex_u64(hal_x86_64::read_efer());
    klog::write_raw(b"\n");
}
