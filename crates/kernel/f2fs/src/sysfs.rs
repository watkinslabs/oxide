//! `/sys/fs/f2fs` — what this filesystem reports about itself and its mounts.
//!
//! Three kinds of directory live here, and the difference between them is the
//! question each answers:
//!
//! - `features/` — what THIS BUILD can do, whatever is mounted. A name is
//!   present when the code behind it is; a name whose feature this build
//!   refuses at mount is absent, because a tool that reads it is deciding
//!   whether to use the feature.
//! - `<dev>/feature_list/` — what THIS VOLUME was formatted with. Every
//!   on-disk feature bit appears, and says `supported` or `unsupported`
//!   according to the volume's own feature word.
//! - `<dev>/` and `<dev>/stat/` — what this MOUNT is doing right now.
//!
//! `<dev>/features` (the comma-separated one) is the older form of the second
//! list, kept because tools still read it.
//!
//! Every value here comes off the live volume. The attributes upstream makes
//! WRITABLE are all knobs of machinery this build does not have — a garbage
//! collector thread with sleep intervals, a discard thread with a policy, a
//! node manager with a memory threshold — and a knob that accepts a value
//! nothing reads is worse than one that is absent, so this surface is
//! entirely read-only.
//!
//! Module manifest:
//! - `build`:        `features/`, and what this build actually implements.
//! - `volume`:       the per-mount attributes, and the two whose text is not
//!                   a number.
//! - `stat`:         `<dev>/stat/`, and the in-memory status word.
//! - `feature_list`: `<dev>/feature_list/`, one entry per on-disk bit.

mod build;
mod feature_list;
mod stat;
pub(crate) mod volume;

#[cfg(test)]
#[path = "tests/sysfs.rs"]
mod tests;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::{dev_id, Attr};
use crate::mount::F2fs;

pub use stat::status_word;

/// The name this filesystem claims under `/sys/fs`. # C: O(1)
pub const SUBSYS: &str = crate::mount::F2FS_NAME;

/// Directories the subsystem holds regardless of what is mounted.
///
/// `tuning` is here with no attributes in it. Upstream's one entry there
/// drives a page-donation reclaim this build has no equivalent of, and an
/// absent directory would say something different from an empty one: that the
/// tuning surface does not exist, rather than that it holds nothing yet.
/// # C: O(1)
pub const GLOBAL_DIRS: &[&str] = &["features", "tuning"];

/// The global attributes — `features/*`. # C: O(N features)
pub fn global_attrs() -> Vec<Attr> { build::attrs() }

/// The directory one mount's attributes live under. # C: O(len)
pub fn mount_dir(source: &str) -> String { dev_id(source) }

/// Every attribute one mount publishes: its own, `stat/` and `feature_list/`.
/// # C: O(N attributes)
pub fn mount_attrs(fs: &Arc<F2fs>) -> Vec<Attr> {
    let dev = mount_dir(fs.source());
    let mut out = volume::attrs(fs, &dev);
    out.extend(stat::attrs(fs, &dev));
    out.extend(feature_list::attrs(fs, &dev));
    out
}
