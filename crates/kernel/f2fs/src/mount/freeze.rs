//! Freezing and thawing one mounted volume.
//!
//! The decision is `sbflags::freeze`; this is the wiring that reads the
//! volume's facts, applies it, and does the two things a thaw owes the
//! device. Everything the pair changes is state, so nothing here is
//! recoverable by retrying: a freeze either raises the mark or reports why it
//! could not.

use vfs::KResult;

use crate::flags::CP_ERROR_FLAG;
use crate::sbflags::freeze::{self, Facts, Outcome};

use super::{errno_to_vfs, F2fs};

impl F2fs {
    /// Seal the volume for a snapshot.
    ///
    /// The checkpoint this needs has already been written: the freeze syncs
    /// the filesystem before it asks, so a volume still dirty here means the
    /// sync did not do what it promised, and sealing over it would name a
    /// state the medium never held.
    /// # C: O(1)
    pub fn freeze(&self) -> KResult<()> {
        let facts = {
            let v = self.volume.lock();
            Facts {
                readonly: !v.writable(),
                cp_error: v.checkpoint().has(CP_ERROR_FLAG),
                dirty: v.is_dirty(),
            }
        };
        match freeze::decide(facts).map_err(errno_to_vfs)? {
            Outcome::Nothing => Ok(()),
            Outcome::Mark => {
                self.volume.lock().set_freezing(true);
                Ok(())
            }
        }
    }

    /// Resume after a freeze.
    ///
    /// No error path, and the reference has none either: the mark comes down
    /// whatever the discards did, because a mark left raised would tell every
    /// later write that a freeze it must not wait for is still running.
    /// # C: O(runs waiting)
    pub fn thaw(&self) {
        let discard = self.volume.lock().options().discard;
        if freeze::thaw_issues_discards(discard, self.supports_discard()) {
            crate::bg::round::drain_discards(self);
        }
        self.volume.lock().set_freezing(false);
    }
}
