//! `/sys/fs/f2fs/features/` — what this build implements.
//!
//! Upstream each entry here reads `supported`, and an entry is compiled in
//! only when the code behind it is. That is the whole contract: a tool reads
//! the directory to decide whether to format or mount with a feature, so a
//! name present for a feature the kernel would refuse sends it into a mount
//! failure it was checking to avoid.
//!
//! So this list is derived from what this crate actually does, not from the
//! set of bits it can name. `KNOWN` in `features` is the wider set — every
//! bit that has been CONSIDERED, including the ones a mount is refused for.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::Attr;

/// Features this build implements, in the order upstream lists them.
///
/// Absent, and why — each is a feature this build would not honour, so
/// claiming it would be a lie a formatter acts on:
///
/// - `encryption`, `test_dummy_encryption_v2`, `encrypted_casefold`: nothing
///   reads the encryption bit; a volume's encrypted files are not decrypted.
/// - `block_zoned`: a zoned volume is refused at mount outright.
/// - `atomic_write`: the atomic-write ioctls do not exist.
/// - `pin_file`: the pin ioctl does not exist; the on-disk hint is only read
///   back during recovery.
/// - `packed_ssa`: the bit is recognised but nothing acts on it.
/// - `fserror`: errors are not recorded into the superblock.
pub const SUPPORTED: &[&str] = &[
    "extra_attr",
    "project_quota",
    "inode_checksum",
    "flexible_inline_xattr",
    "quota_ino",
    "inode_crtime",
    "lost_found",
    "verity",
    "sb_checksum",
    "casefold",
    "readonly",
    "compression",
    "linear_lookup",
];

/// The word every entry in this directory reads.
const SUPPORTED_BODY: &[u8] = b"supported\n";

/// One read-only entry per implemented feature. # C: O(N features)
pub fn attrs() -> Vec<Attr> {
    SUPPORTED.iter()
        .map(|name| Attr::ro("features", name, Arc::new(|| Ok(SUPPORTED_BODY.to_vec()))))
        .collect()
}
