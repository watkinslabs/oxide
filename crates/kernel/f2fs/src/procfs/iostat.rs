//! `iostat_info` — bytes and requests, by the layer that generated them.
//!
//! Empty until the mount is asked to measure, which is a report and not an
//! omission: a table of zeroes would say measurement ran and found no traffic,
//! and the empty file says nothing was measured. The switch is
//! `/sys/fs/f2fs/<dev>/iostat_enable`.

use alloc::sync::Arc;

use crate::fsattr::Attr;
use crate::mount::F2fs;

/// # C: O(N kinds)
pub(crate) fn file(fs: &Arc<F2fs>, dev: &str) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dev, crate::stats::iostat::INFO_NAME, Arc::new(move || {
        // The wall clock is the READER's, taken outside the lock: nothing
        // below this layer can read one, and the volume's own clock is
        // whatever a write last stamped rather than the time now.
        let (secs, _) = crate::mount::write::now();
        let stat = fs.volume.lock().counters().iostat;
        Ok(crate::stats::iostat_info_body(&stat, secs))
    }))
}
