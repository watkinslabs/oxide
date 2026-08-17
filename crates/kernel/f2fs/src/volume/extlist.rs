//! Changing which file extensions this volume places as hot or cold data.
//!
//! The lists are in the SUPERBLOCK, not in the mount options: they are a
//! property of the volume, so a change survives an unmount and is seen by every
//! later mount. That is what makes this a superblock commit rather than a
//! setting — and why the edit is undone when the write is refused, so what the
//! volume reports and what the medium holds cannot disagree.
//!
//! The parse of the written form lives in `place::extlist`, where it can be
//! exercised without a volume.

use syscall::errno::Errno;

use sectors::SectorSource;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Add or remove one extension, in the hot list or the cold one.
    ///
    /// Both copies of the superblock are written, in the order a repair uses,
    /// so a crash between them leaves the volume mounting exactly as it did.
    /// The refusals — an unknown name to remove, a name already in either list,
    /// a full array — are the editor's own, taken before anything reaches the
    /// medium.
    /// # C: O(MAX_EXTENSION), plus one block per superblock copy
    pub fn update_extension_list(&mut self, name: &str, hot: bool, set: bool)
        -> Result<(), Errno> {
        self.writable_or_err()?;
        crate::sbwrite::edit::update_extension_list(&mut self.sb_raw, name, hot, set)?;
        let ro = !self.writable;
        if let Err(e) = crate::sbwrite::commit_super(&self.source, &mut self.sb_raw, false, ro,
                                                    &mut self.sbi) {
            // Put the edit back. A list the medium never took would place new
            // files by a rule no later mount knows about.
            let _ = crate::sbwrite::edit::update_extension_list(&mut self.sb_raw, name, hot, !set);
            return Err(e);
        }
        self.adopt_super()
    }
}

#[cfg(test)]
#[path = "../tests/extlist.rs"]
mod tests;
