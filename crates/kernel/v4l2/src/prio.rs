//! Priority arbitration between open handles of one device.
//!
//! A recording program raises its priority so a preview window cannot change
//! the format underneath it. The state-changing commands consult this before
//! anything else; a handle at a lower priority than the highest one held gets
//! `EBUSY`, which tells it to try again rather than that the command is
//! unsupported.

use core::sync::atomic::{AtomicU32, Ordering};
use syscall::errno::Errno;

use crate::uapi::flags;

/// The set of priorities currently held on one device, as a count per level.
/// Counts rather than a maximum, because a handle dropping its priority must
/// lower the device's only if it was the last holder of that level.
pub struct PrioState {
    background: AtomicU32,
    interactive: AtomicU32,
    record: AtomicU32,
}

impl PrioState {
    /// No handle holding any priority. # C: O(1)
    pub const fn new() -> PrioState {
        PrioState { background: AtomicU32::new(0), interactive: AtomicU32::new(0),
                    record: AtomicU32::new(0) }
    }

    fn slot(&self, prio: u32) -> Option<&AtomicU32> {
        match prio {
            flags::PRIORITY_BACKGROUND => Some(&self.background),
            flags::PRIORITY_INTERACTIVE => Some(&self.interactive),
            flags::PRIORITY_RECORD => Some(&self.record),
            _ => None,
        }
    }

    /// Highest priority any open handle holds. # C: O(1)
    pub fn max(&self) -> u32 {
        if self.record.load(Ordering::Acquire) != 0 { return flags::PRIORITY_RECORD; }
        if self.interactive.load(Ordering::Acquire) != 0 { return flags::PRIORITY_INTERACTIVE; }
        if self.background.load(Ordering::Acquire) != 0 { return flags::PRIORITY_BACKGROUND; }
        flags::PRIORITY_UNSET
    }

    /// Record that a handle now holds `prio`, releasing `previous`. # C: O(1)
    pub fn change(&self, previous: u32, prio: u32) -> Result<(), Errno> {
        let Some(slot) = self.slot(prio) else { return Err(Errno::Einval) };
        slot.fetch_add(1, Ordering::AcqRel);
        if let Some(old) = self.slot(previous) {
            // A count that is already zero means the caller never held the
            // level; leaving it at zero is right, and saturating here keeps a
            // bookkeeping mistake from wrapping into a permanently-held level.
            let _ = old.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                                     |v| Some(v.saturating_sub(1)));
        }
        Ok(())
    }

    /// A handle closed while holding `prio`. # C: O(1)
    pub fn release(&self, prio: u32) {
        if let Some(slot) = self.slot(prio) {
            let _ = slot.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                                      |v| Some(v.saturating_sub(1)));
        }
    }

    /// May a handle at `prio` run a state-changing command?
    ///
    /// Equal priority is allowed: two interactive programs share a device, and
    /// only a strictly higher holder locks the others out.
    /// # C: O(1)
    pub fn check(&self, prio: u32) -> Result<(), Errno> {
        if prio == flags::PRIORITY_UNSET { return Ok(()); }
        if prio < self.max() { return Err(Errno::Ebusy); }
        Ok(())
    }
}

impl Default for PrioState {
    /// # C: O(1)
    fn default() -> Self { PrioState::new() }
}

/// Does this command change device state, and so need a priority check?
///
/// The list is the reference's `INFO_FL_PRIO` set: everything that alters what
/// another handle would see. A command missing from it can be run by any
/// handle at any time.
/// # C: O(1)
pub fn needs_prio(cmd: u64) -> bool {
    use crate::uapi::ioctl::*;
    matches!(cmd,
        VIDIOC_S_FMT | VIDIOC_S_INPUT | VIDIOC_S_STD | VIDIOC_S_CTRL
        | VIDIOC_S_EXT_CTRLS | VIDIOC_S_PARM | VIDIOC_S_CROP | VIDIOC_S_SELECTION
        | VIDIOC_REQBUFS | VIDIOC_CREATE_BUFS | VIDIOC_PREPARE_BUF
        | VIDIOC_STREAMON | VIDIOC_STREAMOFF | VIDIOC_REMOVE_BUFS)
}
