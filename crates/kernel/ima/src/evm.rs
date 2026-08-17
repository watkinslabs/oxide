// Module manifest — EVM, the label over an inode's security metadata.
//
//   xattrs  the protected attribute set, its order, and the metadata block
//   hmac    keyed hashing for the locally computed label
//   verify  the label status ladder and the attribute-write decision

pub mod hmac;
pub mod verify;
pub mod xattrs;

pub use hmac::hmac;
pub use verify::{protect_xattr, verify_label, LabelOps, ProtectCtx, XattrDecision,
                 EVM_HMAC_XATTR_LEN};
pub use xattrs::{count_protected, label_input, misc_block, posix_acl_xattr, protected_xattr,
                 protected_xattr_any, InodeAttrs, Protected, MISC_LEN, PROTECTED};

use alloc::vec::Vec;
use crate::hash::HashAlgo;
use crate::uapi::XattrType;

/// Compute a locally keyed label over an inode's protected attributes and
/// metadata. # C: O(total)
pub fn calc_hmac(
    key: &[u8],
    attrs: &InodeAttrs,
    hmac_attrs: u32,
    xattr_value: impl FnMut(&str) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let input = label_input(XattrType::EvmHmac, attrs, hmac_attrs, xattr_value)?;
    hmac(HashAlgo::Sha1, key, &input)
}

/// Compute the digest a label signature covers. # C: O(total)
pub fn calc_hash(
    ty: XattrType,
    algo: HashAlgo,
    attrs: &InodeAttrs,
    hmac_attrs: u32,
    xattr_value: impl FnMut(&str) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let input = label_input(ty, attrs, hmac_attrs, xattr_value)?;
    algo.digest(&[&input])
}

/// The stored form of a locally keyed label: the type tag followed by the
/// keyed hash. # C: O(n)
pub fn encode_hmac_xattr(digest: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + digest.len());
    v.push(XattrType::EvmHmac.tag());
    v.extend_from_slice(digest);
    v
}

#[cfg(test)]
mod tests;
