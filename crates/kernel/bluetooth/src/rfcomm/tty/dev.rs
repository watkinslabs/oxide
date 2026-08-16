//! The TTY device registry: one entry per `/dev/rfcommN` node bound to a DLC.
//!
//! Identifiers are dense and reusable, and a request may name one or ask for the
//! lowest free one. The list is kept in ascending identifier order, which is
//! what makes "lowest free" a single walk and what the device-list ioctl
//! reports.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::bt::{BdAddr, BT_CLOSED};
use crate::uapi::rfcomm as u;
use super::modem;

/// One bound device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RfcommDev {
    pub id: i16,
    /// The subset of the request's flags a device retains.
    pub flags: u32,
    /// Kernel-internal status bits, not reported to userspace.
    pub status: u32,
    pub src: BdAddr,
    pub dst: BdAddr,
    pub channel: u8,
    /// State of the DLC the device is bound to, which is what the info ioctl
    /// reports as the device's state.
    pub dlc_state: u8,
    /// The peer's signals, already translated to terminal modem bits.
    pub modem_status: u32,
}

impl RfcommDev {
    /// Whether a status bit is set. # C: O(1)
    pub fn status_bit(&self, bit: u32) -> bool { self.status & (1 << bit) != 0 }

    /// Whether a flag bit is set. # C: O(1)
    pub fn flag(&self, bit: u32) -> bool { self.flags & (1 << bit) != 0 }

    /// Adopt the peer's signals, reporting whether the carrier just dropped —
    /// which is the condition that hangs the terminal up. # C: O(1)
    pub fn set_remote_signals(&mut self, v24_sig: u8) -> bool {
        let dropped = modem::carrier_dropped(self.modem_status, v24_sig);
        self.modem_status = modem::v24_to_tiocm(v24_sig);
        dropped
    }
}

/// Every bound device.
#[derive(Default, Debug)]
pub struct DevList { devs: Vec<RfcommDev> }

impl DevList {
    /// An empty registry. # C: O(1)
    pub fn new() -> DevList { DevList { devs: Vec::new() } }

    /// Number of bound devices. # C: O(1)
    pub fn len(&self) -> usize { self.devs.len() }

    /// Whether nothing is bound. # C: O(1)
    pub fn is_empty(&self) -> bool { self.devs.is_empty() }

    /// The device with this identifier. # C: O(n)
    pub fn get(&self, id: i16) -> Option<&RfcommDev> { self.devs.iter().find(|d| d.id == id) }

    /// Mutable access to the device with this identifier. # C: O(n)
    pub fn get_mut(&mut self, id: i16) -> Option<&mut RfcommDev> {
        self.devs.iter_mut().find(|d| d.id == id)
    }

    /// Every device, in identifier order. # C: O(1)
    pub fn iter(&self) -> impl Iterator<Item = &RfcommDev> { self.devs.iter() }

    /// The lowest identifier not in use. # C: O(n)
    pub fn first_free(&self) -> i16 {
        let mut id: i16 = 0;
        for d in self.devs.iter() {
            if d.id != id { break; }
            id += 1;
        }
        id
    }

    /// Bind a device. A request naming an identifier gets that one or fails; a
    /// request with a negative identifier gets the lowest free one. Past the
    /// last node number the request fails rather than wrapping. # C: O(n)
    pub fn add(&mut self, req: &DevReq, dlc_state: u8) -> Result<i16, Errno> {
        let id = if req.dev_id < 0 { self.first_free() } else { req.dev_id };
        if req.dev_id >= 0 && self.get(id).is_some() { return Err(Errno::Eaddrinuse); }
        if id < 0 || id > u::RFCOMM_MAX_DEV - 1 { return Err(Errno::Enfile); }
        let dev = RfcommDev {
            id,
            flags: req.flags & u::RFCOMM_DEV_FLAG_MASK,
            status: 0,
            src: req.src,
            dst: req.dst,
            channel: req.channel,
            dlc_state,
            modem_status: 0,
        };
        let pos = self.devs.iter().position(|d| d.id > id).unwrap_or(self.devs.len());
        self.devs.insert(pos, dev);
        Ok(id)
    }

    /// Release a device. Releasing twice is refused rather than repeated, so a
    /// second releaser cannot tear down a node a third party has since bound.
    /// # C: O(n)
    pub fn release(&mut self, id: i16) -> Result<(), Errno> {
        let Some(d) = self.get_mut(id) else { return Err(Errno::Enodev); };
        if d.status_bit(u::RFCOMM_DEV_RELEASED) { return Err(Errno::Ealready); }
        d.status |= 1 << u::RFCOMM_DEV_RELEASED;
        d.dlc_state = BT_CLOSED;
        let owned = d.status_bit(u::RFCOMM_TTY_OWNED);
        if !owned { self.devs.retain(|d| d.id != id); }
        Ok(())
    }

    /// Whether a device's node is currently open by a terminal, which keeps the
    /// entry alive past its release. # C: O(n)
    pub fn set_tty_owned(&mut self, id: i16, owned: bool) {
        if let Some(d) = self.get_mut(id) {
            if owned { d.status |= 1 << u::RFCOMM_TTY_OWNED; }
            else { d.status &= !(1 << u::RFCOMM_TTY_OWNED); }
        }
    }
}

/// `struct rfcomm_dev_req`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct DevReq {
    pub dev_id: i16,
    pub flags: u32,
    pub src: BdAddr,
    pub dst: BdAddr,
    pub channel: u8,
}

/// `struct rfcomm_dev_info`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct DevInfo {
    pub id: i16,
    pub flags: u32,
    pub state: u16,
    pub src: BdAddr,
    pub dst: BdAddr,
    pub channel: u8,
}

impl DevInfo {
    /// What the info and list ioctls report about a device. # C: O(1)
    pub fn of(dev: &RfcommDev) -> DevInfo {
        DevInfo {
            id: dev.id,
            flags: dev.flags,
            state: dev.dlc_state as u16,
            src: dev.src,
            dst: dev.dst,
            channel: dev.channel,
        }
    }
}
