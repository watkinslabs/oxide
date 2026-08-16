//! The per-file write-priority hint, and the request flags a write carries.
//!
//! A file may be told that its writes matter more than the rest of this
//! mount's traffic. That is all the hint says: the blocks written are
//! identical, the log they come out of is identical, and only the ORDER the
//! device is asked in changes. Nothing here may reach the medium.
//!
//! The hint is deliberately not a task I/O priority. A task's priority is a
//! property of the task and applies to everything it submits; this applies to
//! one file no matter who writes it, and the two must not be able to overwrite
//! each other.

use sectors::SectorSource;

use crate::ioctl::uapi::{IOPRIO_MAX, IOPRIO_WRITE};

use super::Volume;

/// The hint a file with none has.
pub const IOPRIO_NONE: u32 = 0;

/// Whether `level` names a hint a file may be given.
///
/// Ungated and separate from the ioctl so the admission ladder and the setter
/// cannot drift apart about what a valid level is.
/// # C: O(1)
pub fn valid_level(level: u32) -> bool { level < IOPRIO_MAX }

/// The request flags a data write for a file with hint `level` carries.
///
/// Only the write hint produces a flag. A level this build does not recognise
/// produces none rather than something arbitrary: an unknown hint is a request
/// for behaviour that does not exist here, and inventing the most urgent
/// answer for it would let a future level silently become a boost.
/// # C: O(1)
pub fn data_flags(level: u32) -> block::RequestFlags {
    if level == IOPRIO_WRITE { block::flags::PRIO } else { block::RequestFlags::NONE }
}

impl<S: SectorSource> Volume<S> {
    /// The hint `ino` carries, or `IOPRIO_NONE` when it has none. # C: O(log files hinted)
    pub fn io_prio(&self, ino: u32) -> u32 {
        self.ioprio_hint.get(&ino).copied().unwrap_or(IOPRIO_NONE)
    }

    /// Give `ino` a hint, or take its hint away when `level` is `IOPRIO_NONE`.
    ///
    /// Refuses a level it does not know rather than storing it, so the write
    /// path never has to decide what an unrecognised hint means.
    /// # C: O(log files hinted)
    pub fn set_io_prio(&mut self, ino: u32, level: u32) -> Result<(), syscall::errno::Errno> {
        if !valid_level(level) { return Err(syscall::errno::Errno::Einval); }
        if level == IOPRIO_NONE { self.ioprio_hint.remove(&ino); } else { self.ioprio_hint.insert(ino, level); }
        Ok(())
    }

    /// The flags a page of `ino`'s data is written with. # C: O(log files hinted)
    pub(crate) fn data_write_flags(&self, ino: u32) -> block::RequestFlags {
        data_flags(self.io_prio(ino))
    }

    /// Forget every hint for `ino`.
    ///
    /// A hint outliving the inode it was set on would be handed to whichever
    /// file the number is reused for, which is a file nobody asked to boost.
    /// # C: O(log files hinted)
    pub(crate) fn forget_io_prio(&mut self, ino: u32) { self.ioprio_hint.remove(&ino); }
}

#[cfg(test)]
#[path = "../tests/ioprio.rs"]
mod tests;
