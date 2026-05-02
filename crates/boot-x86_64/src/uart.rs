// 16550A UART driver per `36§5` cmdline `oxide.console=ttyS0,115200`
// and `04§4.2` UART sink. COM1 lives at I/O port `0x3f8` on QEMU
// `-serial stdio`; we configure 8N1 + 115200 baud + FIFO enabled at
// boot, then `write_byte` poll-waits on LSR.THRE before each store.
//
// All port I/O asm is cfg-gated to the kernel target; host fallback
// writes to an in-memory recorder so hosted tests can check the
// byte sequence the kernel would emit.
//
// Real PCI/MMIO UART discovery (ACPI SPCR table) lands later in
// `35§*` once ACPI bring-up does.

extern crate alloc;

use klog::Uart;
use sync::{Spinlock, Tty as UartClass};

/// COM1 base I/O port — fixed on PC platforms.
pub const COM1: u16 = 0x3f8;

/// 16550 register offsets from base.
mod reg {
    pub const DATA: u16 = 0; // RBR / THR
    pub const IER:  u16 = 1; // Interrupt Enable
    pub const FCR:  u16 = 2; // FIFO Control
    pub const LCR:  u16 = 3; // Line Control
    pub const MCR:  u16 = 4; // Modem Control
    pub const LSR:  u16 = 5; // Line Status (read)
    pub const DLL:  u16 = 0; // Divisor Latch Low (LCR.DLAB=1)
    pub const DLM:  u16 = 1; // Divisor Latch High
}

const LSR_THRE: u8 = 1 << 5; // Transmit Holding Register Empty

#[inline]
unsafe fn outb(port: u16, val: u8) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: privileged `out` insn legal at CPL=0; the addressed
        // port is COM1's I/O range owned by the boot path. No memory
        // effects beyond the device write.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { record_host(port, val); }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v: u8;
        // SAFETY: privileged `in` insn legal at CPL=0; reads a single
        // byte from the device port. No memory effects.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                out("al") v,
                in("dx") port,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        let _ = port;
        // Pretend THRE is always set so write_byte doesn't spin in tests.
        LSR_THRE
    }
}

/// 16550A UART. `base` is the I/O-port base; `init` programs the
/// device, after which `write_byte` is safe.
pub struct Uart16550 {
    base: u16,
}

impl Uart16550 {
    /// # C: O(1)
    pub const fn new(base: u16) -> Self { Self { base } }

    /// Program the device for 115200 8N1, FIFO enabled, interrupts
    /// disabled. Caller is the boot path; runs once.
    ///
    /// # SAFETY: caller asserts `base` addresses a real 16550-compat
    /// UART and that no other CPU is concurrently driving it.
    /// # C: O(1)
    pub unsafe fn init(&self) {
        // Disable interrupts.
        // SAFETY: the per-port outb/inb wrappers above carry the asm
        // safety contract; this method's contract delegates to them.
        unsafe {
            outb(self.base + reg::IER, 0x00);

            // Enable DLAB to set divisor: 115200 baud ⇒ divisor = 1.
            outb(self.base + reg::LCR, 0x80);
            outb(self.base + reg::DLL, 0x01);
            outb(self.base + reg::DLM, 0x00);

            // 8 bits, no parity, 1 stop, DLAB clear.
            outb(self.base + reg::LCR, 0x03);

            // Enable FIFO, clear them, 14-byte threshold.
            outb(self.base + reg::FCR, 0xc7);

            // RTS/DTR set, IRQs out via OUT2 (legacy; harmless if
            // PIC route disabled).
            outb(self.base + reg::MCR, 0x0b);
        }
    }
}

impl Uart for Uart16550 {
    /// Poll-wait for THRE then write a single byte.
    /// # C: O(spin until ready)
    fn write_byte(&mut self, b: u8) {
        // SAFETY: same contract as `init`; the `inb`/`outb` wrappers
        // own the asm safety. Polling LSR until THRE is the documented
        // 16550 send protocol.
        unsafe {
            while (inb(self.base + reg::LSR) & LSR_THRE) == 0 {
                core::hint::spin_loop();
            }
            outb(self.base + reg::DATA, b);
        }
    }
}

// ---------------------------------------------------------------------------
// Host-side recorder: lets tests observe the byte stream `outb` would
// emit on the kernel target.
// ---------------------------------------------------------------------------

#[cfg(any(test, not(target_os = "oxide-kernel")))]
static HOST_PORTS: Spinlock<alloc::vec::Vec<(u16, u8)>, UartClass>
    = Spinlock::new(alloc::vec::Vec::new());

#[cfg(any(test, not(target_os = "oxide-kernel")))]
fn record_host(port: u16, val: u8) {
    HOST_PORTS.lock().push((port, val));
}

/// Test-only: snapshot every `(port, byte)` recorded since `_reset`.
/// # C: O(N) — copies the recorder vector.
#[cfg(any(test, not(target_os = "oxide-kernel")))]
pub fn host_recorded() -> alloc::vec::Vec<(u16, u8)> {
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
        let u = Uart16550::new(COM1);
        // SAFETY: hosted test; outb path is the recorder, no real I/O.
        unsafe { u.init() };
        let seq = host_recorded();
        // Disable IER + DLAB-on + divisor low + divisor high + LCR clear
        // + FCR + MCR.
        let expected: alloc::vec::Vec<(u16, u8)> = alloc::vec![
            (COM1 + reg::IER, 0x00),
            (COM1 + reg::LCR, 0x80),
            (COM1 + reg::DLL, 0x01),
            (COM1 + reg::DLM, 0x00),
            (COM1 + reg::LCR, 0x03),
            (COM1 + reg::FCR, 0xc7),
            (COM1 + reg::MCR, 0x0b),
        ];
        assert_eq!(seq, expected);
    }

    #[test]
    fn write_byte_emits_data_register_write() {
        let _g = lock();
        _host_reset();
        let mut u = Uart16550::new(COM1);
        u.write_byte(b'A');
        u.write_byte(b'B');
        let seq = host_recorded();
        // Each write hits LSR (recorded? no — `inb` only), then DATA.
        // Recorder only logs writes, so we expect (COM1+DATA, 'A')
        // and (COM1+DATA, 'B').
        let expected: alloc::vec::Vec<(u16, u8)> = alloc::vec![
            (COM1 + reg::DATA, b'A'),
            (COM1 + reg::DATA, b'B'),
        ];
        assert_eq!(seq, expected);
    }

    #[test]
    fn uart_trait_impl_compatible_with_klog() {
        let _g = lock();
        _host_reset();
        let mut u = Uart16550::new(COM1);
        u.write_bytes(b"oxide");
        let bytes: alloc::vec::Vec<u8> = host_recorded().into_iter()
            .filter(|(p, _)| *p == COM1 + reg::DATA)
            .map(|(_, b)| b)
            .collect();
        assert_eq!(&bytes[..], b"oxide");
    }
}
