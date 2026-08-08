// How a boot-console register is reached: port I/O, or memory at one of the
// strides the `earlycon=` grammar names. No `dyn` (`07§5`) — the io type is a
// small enum and the dispatch is a match, so the whole accessor inlines into
// the byte loop and takes no lock and no allocation.

use cmdline::IoType;

/// A bound register file: an io type plus the already-translated base address
/// (a port number for `Port`, a kernel virtual address for the memory types).
pub struct Access {
    io: Kind,
    base: usize,
    stride: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Port,
    Mem,
    Mem16,
    Mem32,
    Mem32Be,
    /// Test backend: records writes instead of touching hardware, so the
    /// register sequences this crate emits are checkable with no UART.
    #[cfg(test)]
    Record,
}

impl Access {
    /// Bind an accessor to `base` for the io type the command line named.
    /// `base` is a port number for `io,` and a kernel VA for the `mmio*`
    /// forms — translation from the physical address the parameter carries is
    /// the caller's job, because only the caller knows the direct map.
    /// # C: O(1)
    pub fn new(io: IoType, base: usize) -> Self {
        let kind = match io {
            IoType::Port => Kind::Port,
            IoType::Mem => Kind::Mem,
            IoType::Mem16 => Kind::Mem16,
            IoType::Mem32 => Kind::Mem32,
            IoType::Mem32Be => Kind::Mem32Be,
        };
        Access { io: kind, base, stride: io.stride() }
    }

    /// Read register `idx` (pre-stride index) as a byte.
    /// # C: O(1)
    pub fn read(&self, idx: u32) -> u8 {
        let off = (idx * self.stride) as usize;
        match self.io {
            Kind::Port => port_in((self.base + off) as u16),
            // SAFETY: `base` is the kernel VA of the UART register file the boot line named, and `off` stays inside the 8-register window this crate addresses; a volatile read of a device register has no memory effect the compiler may reorder away.
            Kind::Mem | Kind::Mem16 => unsafe { core::ptr::read_volatile((self.base + off) as *const u8) },
            // SAFETY: same bound register file as above, read at the 32-bit width the io type selects; the low byte carries the register value.
            Kind::Mem32 => unsafe { core::ptr::read_volatile((self.base + off) as *const u32) as u8 },
            // SAFETY: same bound register file; the big-endian form places the register value in the high byte of the 32-bit word.
            Kind::Mem32Be => unsafe { (core::ptr::read_volatile((self.base + off) as *const u32)).swap_bytes() as u8 },
            #[cfg(test)]
            Kind::Record => recorder::read(idx),
        }
    }

    /// Write `val` to register `idx` (pre-stride index).
    /// # C: O(1)
    pub fn write(&self, idx: u32, val: u8) {
        let off = (idx * self.stride) as usize;
        match self.io {
            Kind::Port => port_out((self.base + off) as u16, val),
            // SAFETY: `base` is the kernel VA of the UART register file the boot line named and `off` stays inside the addressed window; a volatile byte store to a device register is the documented way to drive it.
            Kind::Mem | Kind::Mem16 => unsafe { core::ptr::write_volatile((self.base + off) as *mut u8, val) },
            // SAFETY: same bound register file, stored at the 32-bit access width this io type selects.
            Kind::Mem32 => unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, val as u32) },
            // SAFETY: same bound register file; the big-endian form carries the value in the high byte of the stored word.
            Kind::Mem32Be => unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, (val as u32).swap_bytes()) },
            #[cfg(test)]
            Kind::Record => recorder::write(idx, val),
        }
    }

    /// Read register `idx` as a 32-bit word — the PL011 flag register is read
    /// at full width regardless of io type. # C: O(1)
    pub fn read32(&self, off: usize) -> u32 {
        match self.io {
            Kind::Port | Kind::Mem | Kind::Mem16 | Kind::Mem32 | Kind::Mem32Be =>
                // SAFETY: `base` is the kernel VA of the PL011 register file the boot line named and `off` is one of this crate's fixed register offsets inside it.
                unsafe { core::ptr::read_volatile((self.base + off) as *const u32) },
            #[cfg(test)]
            Kind::Record => recorder::read(off as u32) as u32,
        }
    }

    /// Write a 32-bit word to byte offset `off`. # C: O(1)
    pub fn write32(&self, off: usize, val: u32) {
        match self.io {
            Kind::Port | Kind::Mem | Kind::Mem16 | Kind::Mem32 | Kind::Mem32Be =>
                // SAFETY: same bound PL011 register file and fixed offsets as `read32`; a volatile word store is how the data register is driven.
                unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, val) },
            #[cfg(test)]
            Kind::Record => recorder::write(off as u32, val as u8),
        }
    }

    /// A recording accessor for tests. # C: O(1)
    #[cfg(test)]
    pub fn recording() -> Self { recorder::reset(); Access { io: Kind::Record, base: 0, stride: 1 } }

    /// Every `(register, value)` written through a recording accessor.
    /// # C: O(n)
    #[cfg(test)]
    pub fn recorded(&self) -> std::vec::Vec<(u32, u8)> { recorder::taken() }
}

#[inline]
fn port_in(port: u16) -> u8 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v: u8;
        // SAFETY: the `in` instruction is legal at CPL=0 and the addressed port is the boot-console UART named by the command line; a single byte read from a device port has no memory effect.
        unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)); }
        v
    }
    // Port I/O exists only on the x86 kernel target. Elsewhere report the
    // transmitter as drained so a caller's poll loop terminates.
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = port; crate::uart8250::LSR_THRE | crate::uart8250::LSR_TEMT }
}

#[inline]
fn port_out(port: u16, val: u8) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: the `out` instruction is legal at CPL=0 and the addressed port is the boot-console UART named by the command line; a single byte write to a device port has no memory effect.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags)); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = (port, val); }
}

/// Test recorder. The log is process-global, so every test that uses a
/// recording accessor holds `SERIAL` for its duration — a shared recorder read
/// by concurrently running tests reports another test's register writes, which
/// is a check that cannot fail for the right reason.
#[cfg(test)]
pub mod recorder {
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static LOG: Mutex<Vec<(u32, u8)>> = Mutex::new(Vec::new());
    static REGS: Mutex<Vec<(u32, u8)>> = Mutex::new(Vec::new());
    static SERIAL: Mutex<()> = Mutex::new(());

    /// Hold the recorder for the duration of one test. # C: O(1)
    pub fn serial() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

    /// Drop every recorded write and register value. # C: O(n)
    pub fn reset() {
        LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
        REGS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Record a register write and remember the value for read-back. # C: O(n)
    pub fn write(idx: u32, val: u8) {
        LOG.lock().unwrap_or_else(|e| e.into_inner()).push((idx, val));
        let mut regs = REGS.lock().unwrap_or_else(|e| e.into_inner());
        match regs.iter_mut().find(|(i, _)| *i == idx) { Some(slot) => slot.1 = val, None => regs.push((idx, val)) }
    }

    /// A quiescent port that reads back what was written, so a read-modify-write
    /// sequence behaves as it does on the real device. The 8250 line-status
    /// register is forced to "transmitter drained" so a poll loop terminates.
    /// # C: O(n)
    pub fn read(idx: u32) -> u8 {
        if idx == crate::uart8250::reg::LSR { return crate::uart8250::LSR_THRE | crate::uart8250::LSR_TEMT; }
        REGS.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(i, _)| *i == idx).map(|(_, v)| *v).unwrap_or(0)
    }
    /// Snapshot every recorded write, in order. # C: O(n)
    pub fn taken() -> Vec<(u32, u8)> { LOG.lock().unwrap_or_else(|e| e.into_inner()).clone() }
}
