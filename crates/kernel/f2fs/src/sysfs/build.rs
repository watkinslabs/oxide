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
/// `packed_ssa` belongs here even though no code branches on the bit, and that
/// is conformance rather than an omission. The feature fixes the summary block
/// at four kibibytes instead of taking the volume's block size; a superblock
/// stating any other block size is refused before the feature word is read, so
/// the two sizes are always equal, one summary block always covers one
/// segment, and every derived offset — entry count, journal start, journal
/// length, footer — is the same number either way. The ordinary summary reader
/// IS the packed reader at this block size. Pinned by the two tests over the
/// derived sizes, one asserting the equality and one asserting it is a property
/// of this block size and not of the formulas.
///
/// Absent, and why — a feature this build would not honour, so claiming it
/// would be a lie a formatter acts on:
///
/// - `fserror`: the record that carries errors and stop reasons into the
///   superblock is complete, and no error path calls it, so a volume this
///   mount damages is handed to the next mount looking clean.
pub const SUPPORTED: &[&str] = &[
    "encryption",
    "test_dummy_encryption_v2",
    "encrypted_casefold",
    "block_zoned",
    "atomic_write",
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
    "pin_file",
    "linear_lookup",
    "packed_ssa",
];

/// The word every entry in this directory reads.
const SUPPORTED_BODY: &[u8] = b"supported\n";

/// One read-only entry per implemented feature. # C: O(N features)
pub fn attrs() -> Vec<Attr> {
    SUPPORTED.iter()
        .map(|name| Attr::ro("features", name, Arc::new(|| Ok(SUPPORTED_BODY.to_vec()))))
        .collect()
}
