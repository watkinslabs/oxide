//! `inject_stats` — how many operations each site was made to fail.
//!
//! Every site is listed whether or not it is armed. A report that showed only
//! the armed ones would make "this site never fired" and "this site was never
//! asked to fire" the same absence, and telling those apart is the whole use
//! of the file: a test that arms a site and sees zero has learned that its
//! path was never taken.

use alloc::sync::Arc;

use crate::fsattr::Attr;
use crate::mount::F2fs;

/// # C: O(N sites)
pub(crate) fn file(fs: &Arc<F2fs>, dev: &str) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dev, crate::stats::inject::STATS_NAME, Arc::new(move || {
        let v = fs.volume.lock();
        Ok(crate::stats::inject_stats_body(v.fault_info()))
    }))
}
