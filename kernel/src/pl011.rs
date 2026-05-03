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
