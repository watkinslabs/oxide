//! `/sys/fs/f2fs/<dev>/feature_list/` — one entry per on-disk feature bit.
//!
//! Every bit the format defines appears, whether or not the volume has it and
//! whether or not this build implements it: the question the directory answers
//! is what the volume was FORMATTED with. `supported` means the bit is set in
//! this volume's feature word.
//!
//! That is why the whole bit table lives here and not in `build`, which
//! answers a different question about the same names.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::flags::*;
use crate::fsattr::Attr;
use crate::mount::F2fs;

/// Every on-disk feature bit and the name its entry takes, lowest bit first.
pub(crate) const BITS: &[(u32, &str)] = &[
    (FEATURE_ENCRYPT, "encryption"),
    (FEATURE_BLKZONED, "block_zoned"),
    (FEATURE_ATOMIC_WRITE, "atomic_write"),
    (FEATURE_EXTRA_ATTR, "extra_attr"),
    (FEATURE_PRJQUOTA, "project_quota"),
    (FEATURE_INODE_CHKSUM, "inode_checksum"),
    (FEATURE_FLEXIBLE_INLINE_XATTR, "flexible_inline_xattr"),
    (FEATURE_QUOTA_INO, "quota_ino"),
    (FEATURE_INODE_CRTIME, "inode_crtime"),
    (FEATURE_LOST_FOUND, "lost_found"),
    (FEATURE_VERITY, "verity"),
    (FEATURE_SB_CHKSUM, "sb_checksum"),
    (FEATURE_CASEFOLD, "casefold"),
    (FEATURE_COMPRESSION, "compression"),
    (FEATURE_RO, "readonly"),
    (FEATURE_DEVICE_ALIAS, "device_alias"),
    (FEATURE_PACKED_SSA, "packed_ssa"),
];

/// Bits that get an entry of their own in the directory.
///
/// `atomic_write` is the one bit with no entry upstream — it is not an on-disk
/// property a volume is formatted with — so the two lists differ by it alone.
pub(crate) fn listed() -> impl Iterator<Item = &'static (u32, &'static str)> {
    BITS.iter().filter(|(bit, _)| *bit != FEATURE_ATOMIC_WRITE)
}

const SUPPORTED: &[u8] = b"supported\n";
const UNSUPPORTED: &[u8] = b"unsupported\n";

/// One entry per on-disk bit, reading this volume's own feature word.
/// # C: O(N bits)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    let dir = alloc::format!("{dev}/feature_list");
    listed().map(|(bit, name)| {
        let fs = Arc::clone(fs);
        let bit = *bit;
        Attr::ro(&dir, name, Arc::new(move || {
            let held = fs.volume.lock().super_block().feature & bit != 0;
            Ok(if held { SUPPORTED.to_vec() } else { UNSUPPORTED.to_vec() })
        }))
    }).collect()
}
