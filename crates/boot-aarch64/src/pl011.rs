// PL011 UART driver per `36§5` cmdline `oxide.console=ttyAMA0,115200`
// and `04§4.2` UART sink. On QEMU `virt`, PL011 lives at MMIO base
// `0x0900_0000`. Init sequence: disable → wait BUSY → flush LCR_H →
// program IBRD/FBRD → set 8N1 + FIFO → re-enable. ARM ARM "PrimeCell
// UART (PL011) Technical Reference Manual" Rev. r1p5.
//
// All MMIO ops are cfg-gated to the kernel target; host fallback
// records writes for hosted tests.

extern crate alloc;

use core::ptr;

use klog::Uart;
use sync::{Spinlock, Tty as UartClass};

/// Default PL011 base on the QEMU `virt` machine.
pub const PL011_VIRT_BASE: usize = 0x0900_0000;

/// PL011 register offsets.
mod reg {
    pub const DR:    usize = 0x00; // data
    pub const FR:    usize = 0x18; // flag
    pub const IBRD:  usize = 0x24; // integer baud divisor
    pub const FBRD:  usize = 0x28; // fractional baud divisor
    pub const LCR_H: usize = 0x2c; // line control
    pub const CR:    usize = 0x30; // control
    pub const ICR:   usize = 0x44; // interrupt clear
}

/// FR.TXFF — transmit FIFO full.
const FR_TXFF: u32 = 1 << 5;
/// FR.BUSY — UART busy transmitting.
const FR_BUSY: u32 = 1 << 3;

/// LCR_H bits: word length 8 + FIFO enable.
const LCR_H_8BITS_FIFO: u32 = (0x3 << 5) | (1 << 4);

/// CR bits: RX enable + TX enable + UART enable.
const CR_ENABLE: u32 = (1 << 9) | (1 << 8) | (1 << 0);

#[inline]
unsafe fn mmio_read(addr: usize) -> u32 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: caller asserts `addr` is a PL011 MMIO register
        // owned by the boot path; volatile read sees no compiler
        // reordering with surrounding stores.
        unsafe { ptr::read_volatile(addr as *const u32) }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    {
        let _ = addr;
        // Pretend FR.BUSY is clear and TX FIFO has room.
        0
    }
}

#[inline]
unsafe fn mmio_write(addr: usize, val: u32) {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: caller asserts `addr` is a PL011 MMIO register
        // owned by the boot path; the device byte-orders u32 stores
        // per its TRM.
        unsafe { ptr::write_volatile(addr as *mut u32, val) };
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { record_host(addr, val); }
}

/// PL011 UART. `base` is the MMIO base; `init` programs the device.
pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    /// # C: O(1)
    pub const fn new(base: usize) -> Self { Self { base } }

    /// Initialize the UART for 115200 8N1 with FIFO enabled. Caller
    /// is the boot path.
    ///
    /// # SAFETY: caller asserts `base` addresses a real PL011-compat
    /// device and that no other CPU is concurrently driving it.
    /// # C: O(spin until BUSY=0)
    pub unsafe fn init(&self) {
        // SAFETY: per-fn contract; mmio_{read,write} carry the asm
        // safety contract.
        unsafe {
            // Disable for re-config.
            mmio_write(self.base + reg::CR, 0);
            // Wait for BUSY=0 so the in-flight char drains.
            while (mmio_read(self.base + reg::FR) & FR_BUSY) != 0 {
                core::hint::spin_loop();
            }
            // Flush LCR_H FIFO control before re-program.
            mmio_write(self.base + reg::LCR_H, 0);
            // 24 MHz UART clock on QEMU virt; 115200 baud:
            // divisor = 24_000_000 / (16 * 115200) ≈ 13.020833.
            // IBRD = 13, FBRD = round(0.020833 * 64) = 1.
            mmio_write(self.base + reg::IBRD, 13);
            mmio_write(self.base + reg::FBRD, 1);
            // 8N1, FIFO enabled.
            mmio_write(self.base + reg::LCR_H, LCR_H_8BITS_FIFO);
            // Clear pending interrupts.
            mmio_write(self.base + reg::ICR, 0x7ff);
            // Enable RX/TX/UART.
            mmio_write(self.base + reg::CR, CR_ENABLE);
        }
    }
}

impl Uart for Pl011 {
    /// Poll-wait for TXFF=0 then write a single byte.
    /// # C: O(spin until ready)
    fn write_byte(&mut self, b: u8) {
        // SAFETY: same contract as `init`; the mmio wrappers own the
        // asm safety. PL011 protocol per its TRM §3.2.
        unsafe {
            while (mmio_read(self.base + reg::FR) & FR_TXFF) != 0 {
                core::hint::spin_loop();
            }
            mmio_write(self.base + reg::DR, b as u32);
        }
    }
}

// ---------------------------------------------------------------------------
// Host-side recorder for hosted tests.
// ---------------------------------------------------------------------------

#[cfg(any(test, not(target_os = "oxide-kernel")))]
static HOST_PORTS: Spinlock<alloc::vec::Vec<(usize, u32)>, UartClass>
    = Spinlock::new(alloc::vec::Vec::new());

#[cfg(any(test, not(target_os = "oxide-kernel")))]
fn record_host(addr: usize, val: u32) {
    HOST_PORTS.lock().push((addr, val));
}

/// Test-only: snapshot every `(addr, u32)` recorded since `_reset`.
/// # C: O(N)
#[cfg(any(test, not(target_os = "oxide-kernel")))]
pub fn host_recorded() -> alloc::vec::Vec<(usize, u32)> {
    HOST_PORTS.lock().clone()
}

/// Test-only: clear the recorder.
/// # C: O(1)
#[cfg(any(test, not(target_os = "oxide-kernel")))]
pub fn _host_reset() {
    HOST_PORTS.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static SERIAL: Mutex<()> = Mutex::new(());
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn init_writes_expected_register_sequence() {
        let _g = lock();
        _host_reset();
        let u = Pl011::new(PL011_VIRT_BASE);
        // SAFETY: hosted test; mmio path is the recorder, no real device.
        unsafe { u.init() };
        let seq = host_recorded();
        // Expected: CR=0, LCR_H=0, IBRD=13, FBRD=1, LCR_H=8N1+FIFO,
        // ICR=0x7ff, CR=enable.
        let expected: alloc::vec::Vec<(usize, u32)> = alloc::vec![
            (PL011_VIRT_BASE + reg::CR,    0),
            (PL011_VIRT_BASE + reg::LCR_H, 0),
            (PL011_VIRT_BASE + reg::IBRD,  13),
            (PL011_VIRT_BASE + reg::FBRD,  1),
            (PL011_VIRT_BASE + reg::LCR_H, LCR_H_8BITS_FIFO),
            (PL011_VIRT_BASE + reg::ICR,   0x7ff),
            (PL011_VIRT_BASE + reg::CR,    CR_ENABLE),
        ];
        assert_eq!(seq, expected);
    }

    #[test]
    fn write_byte_emits_data_register_write() {
        let _g = lock();
        _host_reset();
        let mut u = Pl011::new(PL011_VIRT_BASE);
        u.write_byte(b'A');
        u.write_byte(b'B');
        let seq = host_recorded();
        // Recorder only logs writes; FR reads (the polling loop) are
        // not recorded. We expect two DR writes.
        let expected: alloc::vec::Vec<(usize, u32)> = alloc::vec![
            (PL011_VIRT_BASE + reg::DR, b'A' as u32),
            (PL011_VIRT_BASE + reg::DR, b'B' as u32),
        ];
        assert_eq!(seq, expected);
    }

    #[test]
    fn uart_trait_impl_compatible_with_klog() {
        let _g = lock();
        _host_reset();
        let mut u = Pl011::new(PL011_VIRT_BASE);
        u.write_bytes(b"oxide");
        let bytes: alloc::vec::Vec<u8> = host_recorded().into_iter()
            .filter(|(p, _)| *p == PL011_VIRT_BASE + reg::DR)
            .map(|(_, b)| b as u8)
            .collect();
        assert_eq!(&bytes[..], b"oxide");
    }

    #[test]
    fn cr_enable_bits_match_arm_trm() {
        // ARM ARM PL011 r1p5 TRM §3.3.8: bit 0 UARTEN, bit 8 TXE,
        // bit 9 RXE.
        assert_eq!(CR_ENABLE, (1 << 9) | (1 << 8) | (1 << 0));
        assert_eq!(CR_ENABLE, 0x301);
    }

    #[test]
    fn lcr_h_8n1_fifo_bits_match_trm() {
        // §3.3.7: WLEN at bits 6:5; FEN at bit 4.
        assert_eq!(LCR_H_8BITS_FIFO, (0x3 << 5) | (1 << 4));
        assert_eq!(LCR_H_8BITS_FIFO, 0x70);
    }
}
