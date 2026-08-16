// 16550 sleep callbacks (`32a§5` steps 6 and 8, `35`).
//
// A UART loses its whole programming across a context-losing sleep: the
// interrupt enables, the line control, and the divisor latch. Resume has to
// put all three back, and in the order that never leaves a live receiver
// pointed at a half-programmed baud rate — the divisor is written with the
// latch selected, then the line control write both clears the latch and
// re-establishes the frame format, and only then are interrupts re-enabled.
//
// Module manifest:
// - the register file and the save/quiesce/restore triple, generic over the
//   port so the round trip runs hosted;
// - `port`: the real x86 port accessor and the `DevPmOps` table.

use drv::{DevPmOps, Device, KResult};

/// Register offsets from the port base. The first two alias the divisor latch
/// when the line-control register selects it, which is the reason every
/// divisor access is bracketed by a line-control write.
pub const REG_RBR: u16 = 0;
pub const REG_IER: u16 = 1;
pub const REG_FCR: u16 = 2;
pub const REG_LCR: u16 = 3;
pub const REG_MCR: u16 = 4;
pub const REG_LSR: u16 = 5;
/// Divisor latch low half; aliases the receive/transmit register.
pub const REG_DLL: u16 = 0;
/// Divisor latch high half; aliases the interrupt-enable register.
pub const REG_DLM: u16 = 1;

/// Line-control bit 7: the divisor latch is selected in place of the data and
/// interrupt-enable registers.
pub const LCR_DLAB: u8 = 0x80;
/// Line-control bit 6: transmit break. Cleared on the way down so the line is
/// not held low across the sleep.
pub const LCR_BREAK: u8 = 0x40;

/// Every interrupt source masked.
pub const IER_NONE: u8 = 0x00;
/// FIFO control: enabled, both directions cleared.
pub const FCR_RESET: u8 = 0x07;
/// FIFO control bit 0: the FIFOs are in use.
pub const FCR_ENABLE: u8 = 0x01;
/// FIFO control bits 6-7: interrupt at eight received bytes.
pub const FCR_RX_TRIGGER_8: u8 = 0x80;

/// The FIFO-control value this driver programs. That register is write-only —
/// its offset reads back the interrupt identification — so the sleep callbacks
/// save this shadow rather than reading the port.
/// # C: O(1)
pub const fn fifo_mode() -> u8 { FCR_ENABLE | FCR_RX_TRIGGER_8 }

/// A 16550's register file.
pub trait SerialRegs {
    /// Read the register at `off`. # C: O(1)
    fn read(&self, off: u16) -> u8;
    /// Write `v` to the register at `off`. # C: O(1)
    fn write(&mut self, off: u16, v: u8);
}

/// The programming a sleep destroys.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Uart16550State {
    pub ier: u8,
    pub lcr: u8,
    pub mcr: u8,
    /// FIFO control is write-only — reading its offset returns the interrupt
    /// identification — so the value comes from the driver's own shadow.
    pub fcr: u8,
    pub dll: u8,
    pub dlm: u8,
}

/// Read the port's programming. `fcr` is the driver's shadow of the
/// write-only FIFO control register.
/// # C: O(1)
pub fn save<R: SerialRegs>(r: &mut R, fcr: u8) -> Uart16550State {
    let lcr = r.read(REG_LCR);
    r.write(REG_LCR, lcr | LCR_DLAB);
    let dll = r.read(REG_DLL);
    let dlm = r.read(REG_DLM);
    r.write(REG_LCR, lcr);
    Uart16550State { ier: r.read(REG_IER), lcr, mcr: r.read(REG_MCR), fcr, dll, dlm }
}

/// Quiesce the port: mask every interrupt, stop holding the line in break,
/// clear both FIFOs and drain whatever byte the receiver latched.
/// # C: O(1)
pub fn quiesce<R: SerialRegs>(r: &mut R, s: &Uart16550State) {
    r.write(REG_IER, IER_NONE);
    r.write(REG_LCR, s.lcr & !(LCR_DLAB | LCR_BREAK));
    r.write(REG_FCR, FCR_RESET);
    let _ = r.read(REG_RBR);
}

/// Reprogram the port from the saved values: divisor behind the latch, then
/// the line control that closes the latch, then the FIFO and modem control,
/// and the interrupt enables last.
/// # C: O(1)
pub fn restore<R: SerialRegs>(r: &mut R, s: &Uart16550State) {
    r.write(REG_LCR, s.lcr | LCR_DLAB);
    r.write(REG_DLL, s.dll);
    r.write(REG_DLM, s.dlm);
    r.write(REG_LCR, s.lcr);
    r.write(REG_FCR, s.fcr);
    r.write(REG_MCR, s.mcr);
    r.write(REG_IER, s.ier);
}

// ---- the machine's port ----------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod port {
    use super::*;
    use core::sync::atomic::Ordering;
    use sync::{Spinlock, TaskList as PmListClass};

    /// The detected port, addressed through the architecture's I/O space.
    pub struct Port(pub u16);

    impl SerialRegs for Port {
        fn read(&self, off: u16) -> u8 {
            let v: u8;
            // SAFETY: port I/O at CPL 0 against the base this driver detected
            // and published; the sleep callbacks run with the port's other
            // users already stopped.
            unsafe {
                core::arch::asm!("in al, dx", out("al") v, in("dx") self.0 + off,
                                 options(nomem, nostack, preserves_flags));
            }
            v
        }
        fn write(&mut self, off: u16, v: u8) {
            // SAFETY: as the read above; this is the driver's own detected
            // port and the caller owns it exclusively for the transition.
            unsafe {
                core::arch::asm!("out dx, al", in("dx") self.0 + off, in("al") v,
                                 options(nomem, nostack, preserves_flags));
            }
        }
    }

    pub static SAVED: Spinlock<Option<Uart16550State>, PmListClass> = Spinlock::new(None);

    /// The live port, or `None` when nothing was detected. # C: O(1)
    pub fn detected() -> Option<Port> {
        let b = super::super::BASE.load(Ordering::Acquire) as u16;
        if b == 0 { None } else { Some(Port(b)) }
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod port {
    use super::*;
    use sync::{Spinlock, TaskList as PmListClass};

    /// No 16550 off x86; the accessor exists so the callbacks compile.
    pub struct Port;
    impl SerialRegs for Port {
        fn read(&self, _off: u16) -> u8 { 0 }
        fn write(&mut self, _off: u16, _v: u8) {}
    }
    pub static SAVED: Spinlock<Option<Uart16550State>, PmListClass> = Spinlock::new(None);
    /// No port off x86. # C: O(1)
    pub fn detected() -> Option<Port> { None }
}

fn do_suspend(_dev: &Device) -> KResult<()> {
    let Some(mut p) = port::detected() else { return Ok(()) };
    let s = save(&mut p, fifo_mode());
    quiesce(&mut p, &s);
    *port::SAVED.lock() = Some(s);
    Ok(())
}

fn do_resume(_dev: &Device) -> KResult<()> {
    let saved = *port::SAVED.lock();
    let (Some(s), Some(mut p)) = (saved, port::detected()) else { return Ok(()) };
    restore(&mut p, &s);
    Ok(())
}

/// The 16550's sleep callbacks. Hibernation shares the system-sleep pair: the
/// port's programming is reproduced from the saved values either way, and the
/// device holds no image-dependent state that would make the two differ.
pub static PM_OPS: DevPmOps = DevPmOps {
    suspend: Some(do_suspend), resume: Some(do_resume),
    freeze: Some(do_suspend), thaw: Some(do_resume),
    poweroff: Some(do_suspend), restore: Some(do_resume),
    ..DevPmOps::none()
};

#[cfg(test)]
#[path = "pm/tests.rs"]
mod tests;
