//! `/sys/fs/ext4` — what this filesystem reports about itself and its mounts.
//!
//! Two kinds of directory live here, and the difference is the question each
//! answers:
//!
//! - `features/` — what THIS BUILD can do, whatever is mounted. A name is
//!   present when the code behind it is, and says `supported`; a name whose
//!   feature this build does not implement is ABSENT, because a tool reading
//!   it is deciding whether to use the feature.
//! - `<dev>/` — what one MOUNT is doing right now: how much has been written
//!   to the volume, and what it has found wrong with itself.
//!
//! The per-mount directory is named for the block device the mount came from,
//! which is the name this kernel already answers when a program asks a file
//! which sysfs directory describes its filesystem. A mount whose device is not
//! a registered disk gets no directory rather than one under an invented name.
//!
//! Module manifest:
//! - `build`:  `features/`, and what this build actually implements.
//! - `disk`:   which registered disk a mount is on, and its write counters.
//! - `errors`: the volume's error history, as the reports that read it.
//! - `volume`: the per-mount reports about writes.

mod build;
pub mod disk;
mod errors;
mod volume;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::Attr;
use crate::rootfs::RootfsState;

/// The name this filesystem claims under `/sys/fs`. # C: O(1)
pub const SUBSYS: &str = "ext4";

/// Directories the subsystem holds regardless of what is mounted. # C: O(1)
pub const GLOBAL_DIRS: &[&str] = &["features"];

/// The global attributes — `features/*`. # C: O(N features)
pub fn global_attrs() -> Vec<Attr> { build::attrs() }

/// The directory one mount's attributes live under, or `None` when the mount
/// is not on a registered disk and so has no name to publish under.
/// # C: O(N disks)
pub fn mount_dir(st: &Arc<RootfsState>) -> Option<String> { disk::name_of(&st.mount) }

/// Every attribute one mount publishes. # C: O(N attributes)
pub fn mount_attrs(st: &Arc<RootfsState>) -> Vec<Attr> {
    let Some(dev) = mount_dir(st) else { return Vec::new() };
    let mut out = volume::attrs(st, &dev);
    out.extend(errors::attrs(st, &dev));
    out
}
