// PL011 sleep callbacks (`32a§5` steps 6 and 8, `35`).
//
// The order the baud registers go back in is architectural, not a preference:
// the line-control register latches the divisor, so both halves of the divisor
// must already be written when it is. The control register is written last,
// because it is what re-enables the transmitter and receiver, and the
// interrupt mask after that, because a port that is enabled but not yet
// unmasked simply queues — one that is unmasked but not yet configured
// delivers noise.
//
// Module manifest:
// - the register file and the save/quiesce/restore triple, generic over the
//   window so the round trip runs hosted;
// - `window`: the real memory-mapped accessor and the `DevPmOps` table.

use drv::{DevPmOps, Device, KResult};

/// Register offsets from the PL011 base.
pub const REG_DR:    usize = 0x00;
pub const REG_FR:    usize = 0x18;
pub const REG_IBRD:  usize = 0x24;
pub const REG_FBRD:  usize = 0x28;
pub const REG_LCRH:  usize = 0x2C;
pub const REG_CR:    usize = 0x30;
pub const REG_IFLS:  usize = 0x34;
pub const REG_IMSC:  usize = 0x38;
pub const REG_ICR:   usize = 0x44;
pub const REG_DMACR: usize = 0x48;

/// Control bit 0: the port is enabled.
pub const CR_UARTEN: u32 = 1 << 0;
/// Control bit 8: the transmitter is enabled.
pub const CR_TXE: u32 = 1 << 8;
/// Control bit 9: the receiver is enabled.
pub const CR_RXE: u32 = 1 << 9;
/// Control bits 10-11: the modem handshake outputs, preserved across a
/// quiesce so a peer does not see the line drop.
pub const CR_HANDSHAKE: u32 = (1 << 10) | (1 << 11);

/// Line-control bit 0: transmit break.
pub const LCRH_BRK: u32 = 1 << 0;
/// Line-control bit 4: the FIFOs are in use.
pub const LCRH_FEN: u32 = 1 << 4;

/// Every interrupt source masked.
pub const IMSC_NONE: u32 = 0;
/// Every interrupt source cleared; the clear register is write-one-to-clear
/// across its eleven implemented bits.
pub const ICR_ALL: u32 = 0x7FF;

/// A PL011's register window.
pub trait Pl011Regs {
    /// Read the register at `off`. # C: O(1)
    fn read(&self, off: usize) -> u32;
    /// Write `v` to the register at `off`. # C: O(1)
    fn write(&mut self, off: usize, v: u32);
}

/// The programming a sleep destroys.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Pl011State {
    pub cr: u32,
    pub lcrh: u32,
    pub ibrd: u32,
    pub fbrd: u32,
    pub imsc: u32,
}

/// Read the port's programming. # C: O(1)
pub fn save<R: Pl011Regs>(r: &R) -> Pl011State {
    Pl011State {
        cr: r.read(REG_CR),
        lcrh: r.read(REG_LCRH),
        ibrd: r.read(REG_IBRD),
        fbrd: r.read(REG_FBRD),
        imsc: r.read(REG_IMSC),
    }
}

/// Quiesce the port: mask and clear every interrupt, drop the receiver and the
/// FIFOs, and keep only the transmitter and the handshake outputs live so a
/// late console write still lands.
/// # C: O(1)
pub fn quiesce<R: Pl011Regs>(r: &mut R, s: &Pl011State) {
    r.write(REG_IMSC, IMSC_NONE);
    r.write(REG_ICR, ICR_ALL);
    r.write(REG_CR, (s.cr & CR_HANDSHAKE) | CR_UARTEN | CR_TXE);
    r.write(REG_LCRH, s.lcrh & !(LCRH_BRK | LCRH_FEN));
}

/// Reprogram the port: both halves of the divisor, then the line control that
/// latches them, then the control register, then the interrupt mask.
/// # C: O(1)
pub fn restore<R: Pl011Regs>(r: &mut R, s: &Pl011State) {
    r.write(REG_IMSC, IMSC_NONE);
    r.write(REG_ICR, ICR_ALL);
    r.write(REG_FBRD, s.fbrd);
    r.write(REG_IBRD, s.ibrd);
    r.write(REG_LCRH, s.lcrh);
    r.write(REG_CR, s.cr);
    r.write(REG_IMSC, s.imsc);
}

// ---- the machine's window --------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod window {
    use super::*;
    use core::sync::atomic::Ordering;
    use sync::{Spinlock, TaskList as PmListClass};

    /// The published PL011 mapping.
    pub struct Window(pub u64);

    impl Pl011Regs for Window {
        fn read(&self, off: usize) -> u32 {
            // SAFETY: `self.0` is the live device mapping this driver
            // published at probe, and `off` is a register inside the 4 KiB
            // PL011 frame; the sleep callbacks own the port exclusively.
            unsafe { core::ptr::read_volatile((self.0 + off as u64) as *const u32) }
        }
        fn write(&mut self, off: usize, v: u32) {
            // SAFETY: as the read above; the caller has already stopped every
            // other user of the port for the duration of the transition.
            unsafe { core::ptr::write_volatile((self.0 + off as u64) as *mut u32, v) }
        }
    }

    pub static SAVED: Spinlock<Option<Pl011State>, PmListClass> = Spinlock::new(None);

    /// The live port, or `None` when nothing was published. # C: O(1)
    pub fn detected() -> Option<Window> {
        let b = super::super::BASE.load(Ordering::Acquire);
        if b == 0 { None } else { Some(Window(b)) }
    }
}

#[cfg(not(target_arch = "aarch64"))]
mod window {
    use super::*;
    use sync::{Spinlock, TaskList as PmListClass};

    /// No PL011 off arm; the accessor exists so the callbacks compile.
    pub struct Window;
    impl Pl011Regs for Window {
        fn read(&self, _off: usize) -> u32 { 0 }
        fn write(&mut self, _off: usize, _v: u32) {}
    }
    pub static SAVED: Spinlock<Option<Pl011State>, PmListClass> = Spinlock::new(None);
    /// No port off arm. # C: O(1)
    pub fn detected() -> Option<Window> { None }
}

fn do_suspend(_dev: &Device) -> KResult<()> {
    let Some(mut w) = window::detected() else { return Ok(()) };
    let s = save(&w);
    quiesce(&mut w, &s);
    *window::SAVED.lock() = Some(s);
    Ok(())
}

fn do_resume(_dev: &Device) -> KResult<()> {
    let saved = *window::SAVED.lock();
    let (Some(s), Some(mut w)) = (saved, window::detected()) else { return Ok(()) };
    restore(&mut w, &s);
    Ok(())
}

/// The PL011's sleep callbacks. Hibernation shares the system-sleep pair: the
/// port is reprogrammed from the saved values either way.
pub static PM_OPS: DevPmOps = DevPmOps {
    suspend: Some(do_suspend), resume: Some(do_resume),
    freeze: Some(do_suspend), thaw: Some(do_resume),
    poweroff: Some(do_suspend), restore: Some(do_resume),
    ..DevPmOps::none()
};

#[cfg(test)]
#[path = "pm/tests.rs"]
mod tests;
