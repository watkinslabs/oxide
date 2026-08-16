//! Emptying one member device onto the others.
//!
//! The request names a member and a number of segments; the work is to clean
//! that many of the member's segments, so that the blocks living on it move to
//! whichever member the allocator picks next. Repeated requests walk the
//! member, which is why the cursor survives between them — restarting at the
//! member's first segment each time would re-clean what is already empty and
//! never reach the end.
//!
//! Two things here are not obvious and both come from the same place. The
//! ordinary victim search is pushed PAST the window before any cleaning
//! starts: a search that walked back into the range being emptied would
//! choose a victim there and write the blocks straight back onto the member
//! being emptied. And a segment that yields nothing is not a failure — it is
//! the ordinary outcome for a segment whose live blocks nothing can move —
//! so the walk continues rather than reporting the member unemptied.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Clean up to `segments` of member `dev_num`'s segments, resuming where
    /// the last request stopped.
    ///
    /// The window is arithmetic on the member's span; admission has already
    /// refused a volume with one member, a member index with nothing after
    /// it, and a section wider than a segment.
    /// # C: O(segments × blocks per segment)
    pub fn flush_device(&mut self, dev_num: usize, segments: u32) -> Result<(), Errno> {
        self.writable_or_err()?;
        let cursor = self.segstate.flush_dev_cursor;
        let (start, end) = self
            .flush_device_window(dev_num, segments, cursor)
            .ok_or(Errno::Einval)?;
        let mut segno = start;
        while segno < end {
            self.segstate.gc_cursor = end.saturating_add(1);
            // The cursor records the segment ATTEMPTED, not the one after it,
            // so a request that stops early resumes on the same segment
            // rather than stepping over it.
            self.segstate.flush_dev_cursor = segno;
            match self.gc_section(segno) {
                Ok(_) => {}
                // Nothing could be taken from this one; the next may still
                // give something up.
                Err(Errno::Eagain) => {}
                Err(e) => return Err(e),
            }
            segno += 1;
        }
        Ok(())
    }
}
