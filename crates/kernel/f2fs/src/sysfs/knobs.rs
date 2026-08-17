//! `/sys/fs/f2fs/<dev>/` — the controls, as opposed to the reports.
//!
//! Every entry here turns a knob of the cleaner or the discard thread, and is
//! writable for exactly that reason: the machinery behind it exists and reads
//! the value on its next round. A control whose value nothing read would be
//! worse than an absent one, because a tool that set it would believe it had
//! changed something.
//!
//! Values are refused, never clamped. `bg::knobs` owns which values each takes
//! and this file owns only the plumbing, so the bounds are checkable without a
//! mount and cannot drift from what the threads actually accept.

use alloc::sync::Arc;

use crate::bg::knobs::{self, Knob};
use crate::fsattr::{line_u64, Attr};
use crate::mount::{errno_to_vfs, F2fs};

/// One control, bound to the mount whose threads it turns. # C: O(1)
fn knob(fs: &Arc<F2fs>, dir: &str, k: Knob) -> Attr {
    let show_fs = Arc::clone(fs);
    let store_fs = Arc::clone(fs);
    Attr::rw(
        dir,
        knobs::name(k),
        Arc::new(move || Ok(line_u64(knobs::show(show_fs.bg(), k)))),
        Arc::new(move |bytes: &[u8]| {
            let v = knobs::parse_value(bytes).map_err(errno_to_vfs)?;
            let atgc = store_fs.options().atgc;
            knobs::store(store_fs.bg(), k, v, atgc).map_err(errno_to_vfs)?;
            Ok(bytes.len())
        }),
    )
}

/// Every control one mount publishes. # C: O(N controls)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> alloc::vec::Vec<Attr> {
    knobs::ALL.iter().map(|&k| knob(fs, dev, k)).collect()
}
