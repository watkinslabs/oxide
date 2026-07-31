// Kernel-side PL011 UART sink for aarch64.
//
// Once `kernel_main` has PMM up + the device mapper, we install a
// Device-nGnRnE 4 KiB mapping over the PL011 phys base, init the
// chip for 115200 8N1 + FIFO, and swap the klog byte-sink from the
// boot crate's semihosting fallback to this real driver. Subsequent
// klog records reach `-serial stdio` directly without trapping into
// QEMU semihosting on every byte.
//
// Once VMM lands a real device-mapping API per `21§5`, this can
// reuse it; the inline mapping site here is the smallest interface
// surface between the kernel and the in-flight device-page mapper.

#[cfg(target_os = "oxide-kernel")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "oxide-kernel")]
const PL011_DR:    usize = 0x00;
#[cfg(target_os = "oxide-kernel")]
const PL011_FR:    usize = 0x18;
#[cfg(target_os = "oxide-kernel")]
const PL011_IBRD:  usize = 0x24;
#[cfg(target_os = "oxide-kernel")]
const PL011_FBRD:  usize = 0x28;
#[cfg(target_os = "oxide-kernel")]
const PL011_LCR_H: usize = 0x2c;
#[cfg(target_os = "oxide-kernel")]
const PL011_CR:    usize = 0x30;
#[cfg(target_os = "oxide-kernel")]
const PL011_ICR:   usize = 0x44;
#[cfg(target_os = "oxide-kernel")]
const PL011_IMSC:  usize = 0x38;
/// Masked interrupt status (`UARTMIS`) — raw status ANDed with `UARTIMSC`.
#[cfg(target_os = "oxide-kernel")]
const PL011_MIS:   usize = 0x40;

/// `UARTIMSC`/`UARTMIS` bit 4: receive interrupt (FIFO at its trigger level).
#[cfg(target_os = "oxide-kernel")]
const IMSC_RXIM: u32 = 1 << 4;
/// `UARTIMSC`/`UARTMIS` bit 6: receive-timeout interrupt (FIFO non-empty and
/// idle for 32 bit-periods) — how a typed line shorter than the trigger level
/// is reported at all.
#[cfg(target_os = "oxide-kernel")]
const IMSC_RTIM: u32 = 1 << 6;

#[cfg(target_os = "oxide-kernel")]
const FR_TXFF: u32 = 1 << 5;
#[cfg(target_os = "oxide-kernel")]
const FR_BUSY: u32 = 1 << 3;
#[cfg(target_os = "oxide-kernel")]
const LCR_H_8BITS_FIFO: u32 = (0x3 << 5) | (1 << 4);
#[cfg(target_os = "oxide-kernel")]
const CR_ENABLE: u32 = (1 << 9) | (1 << 8) | (1 << 0);

/// PL011 base VA after `set_base` runs. `0` means "not yet mapped";
/// `pl011_emit` is a no-op in that window. Atomic so the swap is
/// race-free relative to klog readers (single-CPU still, but lays
/// the ground for SMP).
#[cfg(target_os = "oxide-kernel")]
static PL011_BASE_VA: AtomicU64 = AtomicU64::new(0);

/// PL011 `UARTCLK` (Hz), resolved from the DTB clock tree at boot
/// (`boot-aarch64::dtb::pl011_clock_hz`) and consumed by the runtime driver's
/// TCSETS baud reprogram. Seeded to the qemu-virt / near-universal 24 MHz
/// fallback so a DTB without an explicit PL011 clock still programs a correct
/// divisor. Published here (beside `PL011_BASE_VA`) because both boot and the
/// driver already depend on this crate.
static PL011_UARTCLK_HZ: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(24_000_000);

/// Publish the DTB-resolved PL011 `UARTCLK` (Hz). `0` is ignored (keeps the
/// fallback). Called once at boot after the DTB is parsed. # C: O(1)
pub fn set_uartclk_hz(hz: u32) {
    if hz != 0 { PL011_UARTCLK_HZ.store(hz, core::sync::atomic::Ordering::Release); }
}

/// The resolved PL011 `UARTCLK` (Hz) — the DTB rate, or the 24 MHz fallback.
/// # C: O(1)
pub fn uartclk_hz() -> u32 { PL011_UARTCLK_HZ.load(core::sync::atomic::Ordering::Acquire) }

/// Initialize the chip for 115200 8N1 + FIFO at the given mapped VA,
/// then publish so `pl011_emit` becomes the live klog sink path.
///
/// # SAFETY: caller asserts `va` is a freshly-installed Device-attr
/// mapping covering the PL011 register page; runs single-CPU,
/// IRQ-off; no other path is touching the device.
/// # C: O(spin until BUSY=0)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn enable(va: u64) {
    // SAFETY: per fn contract — `va` is a fresh Device-attr 4 KiB mapping over the PL011 register page; sequence per ARM ARM PL011 r1p5 §3.2.
    unsafe {
        write_reg(va, PL011_CR, 0);
        while (read_reg(va, PL011_FR) & FR_BUSY) != 0 {
            core::hint::spin_loop();
        }
        write_reg(va, PL011_LCR_H, 0);
        // 24 MHz UART clock on QEMU virt; 115200 baud → IBRD=13, FBRD=1.
        write_reg(va, PL011_IBRD, 13);
        write_reg(va, PL011_FBRD, 1);
        write_reg(va, PL011_LCR_H, LCR_H_8BITS_FIFO);
        write_reg(va, PL011_ICR, 0x7ff);
        write_reg(va, PL011_CR, CR_ENABLE);
    }
    PL011_BASE_VA.store(va, Ordering::Release);
}

#[cfg(target_os = "oxide-kernel")]
unsafe fn write_reg(va: u64, off: usize, val: u32) {
    // SAFETY: per fn contract; `(va + off)` lies inside the 4 KiB
    // PL011 register page mapped Device-nGnRnE.
    unsafe { core::ptr::write_volatile((va + off as u64) as *mut u32, val); }
}

#[cfg(target_os = "oxide-kernel")]
unsafe fn read_reg(va: u64, off: usize) -> u32 {
    // SAFETY: same contract as write_reg — `va + off` is inside the 4 KiB Device-nGnRnE PL011 register page.
    unsafe { core::ptr::read_volatile((va + off as u64) as *const u32) }
}

/// Current PL011 base VA — `0` if `enable` hasn't run yet.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn base_va() -> u64 { PL011_BASE_VA.load(Ordering::Acquire) }

/// Enable PL011 RX + RX-timeout IRQs by setting `UARTIMSC` bits 4
/// (RXIM) + 6 (RTIM). After this the device asserts SPI 33 on the
/// GIC whenever bytes arrive in the FIFO; pair with
/// `gic::enable_intid(33)` so the distributor delivers them.
///
/// # SAFETY: caller asserts `enable` has run; runs single-CPU,
/// IRQ-off; UARTIMSC offset 0x38 lives inside the mapped page.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn enable_rx_irq() {
    let va = PL011_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return; }
    // SAFETY: per fn contract; aligned u32 RMW within the 4 KiB Device-nGnRnE PL011 register page.
    unsafe {
        let cur = read_reg(va, PL011_IMSC);
        write_reg(va, PL011_IMSC, cur | IMSC_RXIM | IMSC_RTIM);
    }
}

/// Disable PL011 RX + RX-timeout IRQs.
///
/// # SAFETY: caller owns PL011 teardown; UARTIMSC lives inside the mapped page.
/// # C: O(1)
/// # Ctx: driver remove / boot teardown
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn disable_rx_irq() {
    let va = PL011_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return; }
    // SAFETY: per fn contract; aligned u32 RMW within the PL011 register page.
    unsafe {
        let cur = read_reg(va, PL011_IMSC);
        write_reg(va, PL011_IMSC, cur & !(IMSC_RXIM | IMSC_RTIM));
    }
}

/// Masked RX + RX-timeout interrupt status (`UARTMIS`, offset 0x40): true
/// while the device is still asking to be serviced. The IRQ handler re-checks
/// this after draining the FIFO instead of writing `UARTICR` — both interrupts
/// are cleared by emptying the FIFO, and a post-drain write to `UARTICR`
/// discards the indication for bytes that arrived during the drain, leaving
/// data in the FIFO that nothing will ever report.
///
/// # SAFETY: caller is the IRQ dispatcher; `enable` has run.
/// # C: O(1)
/// # Ctx: IRQ
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn rx_irq_pending() -> bool {
    let va = PL011_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return false; }
    // SAFETY: per fn contract; UARTMIS (0x40) is within the mapped 4 KiB Device-nGnRnE page.
    let mis = unsafe { read_reg(va, PL011_MIS) };
    (mis & (IMSC_RXIM | IMSC_RTIM)) != 0
}

/// klog `LogSink` thunk. No-op if `enable` hasn't run yet.
/// # C: O(len)
#[cfg(target_os = "oxide-kernel")]
pub fn pl011_emit(bytes: &[u8]) {
    let va = PL011_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return; }
    for &b in bytes {
        // SAFETY: `va` is the published kernel VA from a prior
        // `enable` call; reads/writes live within the 4 KiB device
        // page mapped Device-nGnRnE.
        unsafe {
            while (read_reg(va, PL011_FR) & FR_TXFF) != 0 {
                core::hint::spin_loop();
            }
            write_reg(va, PL011_DR, b as u32);
        }
    }
}
