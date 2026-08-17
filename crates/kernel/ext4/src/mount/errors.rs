//! The mount's half of the volume's error history: adding an event to it, and
//! handing a reader a snapshot of it.
//!
//! The rules about what an event does to the history live in `errstat`, which
//! has no mount behind it and is answered under `cargo test`. What is here is
//! the part that needs the live mount — the clock, and the lock.

use crate::errstat::{ErrEvent, ErrRecord};
use crate::{Mount, MountError};

impl Mount {
    /// Add one filesystem error to this volume's history.
    ///
    /// The event carries no inode or block: the one place errors are reported
    /// from is handed the failure, not the object it was found on, so a number
    /// here would be invented. Zero is what the record means by "the site did
    /// not name one".
    /// # C: O(1)
    pub(crate) fn record_error(&self, e: &MountError) {
        let secs = vfs::inode_times::realtime_now_ns() / NS_PER_SEC;
        self.err.lock().record(ErrEvent {
            time_secs: secs,
            ino:       0,
            block:     0,
            errcode:   crate::errstat::code_for(e),
        });
    }

    /// This volume's error history as it stands. # C: O(1)
    pub fn error_record(&self) -> ErrRecord { *self.err.lock() }
}

const NS_PER_SEC: u64 = 1_000_000_000;
