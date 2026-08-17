//! `/proc/fs/ntfs3/<dev>/` — what one mounted volume says about itself.
//!
//! Two files, and they are the whole of this filesystem's `/proc` surface:
//!
//! - `volinfo`, seven lines that a tool reads positionally, so the ORDER is
//!   the format: the version, the cluster size, the clusters, the records the
//!   MFT holds, the records in use, whether the volume needs a check, and
//!   whether it is currently flagged dirty.
//! - `label`, the volume's name — the one entry here that is a control as well
//!   as a report, because writing the name to it is how a volume is renamed.
//!
//! The last two lines of `volinfo` differ, and the difference is the point:
//! the first says whether this volume needed a check when it was found, the
//! second says what its flag reads now. A writable mount sets the flag itself
//! and clears it again at unmount, so the second alone would call every live
//! volume dirty and every unmounted one clean.
//!
//! Module manifest:
//! - `volinfo`: the report, and the snapshot it renders from.
//! - `label`:   the name, read and written.

mod label;
mod volinfo;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::{dev_id, Attr};
use crate::mount::NtfsFs;

pub use volinfo::{volinfo_body, VolInfo};

/// The name this filesystem claims under `/proc/fs`. # C: O(1)
pub const FS_NAME: &str = crate::mount::NTFS_NAME;

/// The directory one mount's files live under. # C: O(len)
pub fn mount_dir(source: &str) -> String { dev_id(source) }

/// Every file one mount publishes. # C: O(1)
pub fn mount_files(fs: &Arc<NtfsFs>) -> Vec<Attr> {
    let dev = mount_dir(fs.source());
    alloc::vec![volinfo::file(fs, &dev), label::file(fs, &dev)]
}
