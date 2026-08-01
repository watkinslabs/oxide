// Module manifest:
// - parse: option-table coverage + journalled-quota-file name rules.
// - consistency: every rejected option combination and its errno.
// - apply: how an accepted context lands on superblock quota option state.

mod parse;
mod consistency;
mod apply;

use alloc::string::String;

use super::{Ext4MountOpts, FsQuotaFeatures, SbQuotaOpts};

/// Filesystem with neither the QUOTA nor the PROJECT feature. # C: O(1)
pub(super) fn plain() -> FsQuotaFeatures { FsQuotaFeatures { quota: false, project: false } }
/// Filesystem with the PROJECT feature only. # C: O(1)
pub(super) fn project() -> FsQuotaFeatures { FsQuotaFeatures { quota: false, project: true } }
/// Filesystem with kernel-owned hidden quota inodes. # C: O(1)
pub(super) fn hidden() -> FsQuotaFeatures { FsQuotaFeatures { quota: true, project: true } }

/// Parse + intra-string validation, the pre-superblock half of a mount. # C: O(len)
pub(super) fn parsed(data: &str) -> vfs::KResult<Ext4MountOpts> {
    let mut o = Ext4MountOpts::parse(data)?;
    o.validate()?;
    Ok(o)
}

/// Live superblock state carrying `names` and `fmt`. # C: O(1)
pub(super) fn live(names: [Option<&str>; 3], fmt: u32, mount_opt: u32) -> SbQuotaOpts {
    SbQuotaOpts {
        mount_opt,
        qf_names: names.map(|n| n.map(String::from)),
        jquota_fmt: fmt,
    }
}
