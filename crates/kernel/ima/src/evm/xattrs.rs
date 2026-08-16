// What the EVM label covers: an ordered set of security extended attributes,
// followed by a fixed block of inode metadata.
//
// Order is part of the contract — the label is a hash over the values in this
// exact sequence, so moving an entry invalidates every existing label. So is
// the metadata block's layout: it is a C structure image, including the pad
// that follows its trailing 16-bit mode field.

use alloc::vec::Vec;

use crate::flags::EVM_ATTR_FSUUID;
use crate::uapi::{XattrType, XATTR_NAME_APPARMOR, XATTR_NAME_CAPS, XATTR_NAME_IMA,
                  XATTR_NAME_SELINUX, XATTR_NAME_SMACK, XATTR_NAME_SMACK_EXEC,
                  XATTR_NAME_SMACK_MMAP, XATTR_NAME_SMACK_TRANSMUTE};

/// A protected attribute and whether this configuration includes it in locally
/// computed labels. A portable signature covers every protected name whether
/// enabled or not, because it must verify on a system configured differently.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Protected {
    pub name: &'static str,
    pub enabled: bool,
}

/// The protected set, in label order.
pub const PROTECTED: [Protected; 8] = [
    Protected { name: XATTR_NAME_SELINUX, enabled: true },
    Protected { name: XATTR_NAME_SMACK, enabled: false },
    Protected { name: XATTR_NAME_SMACK_EXEC, enabled: false },
    Protected { name: XATTR_NAME_SMACK_TRANSMUTE, enabled: false },
    Protected { name: XATTR_NAME_SMACK_MMAP, enabled: false },
    Protected { name: XATTR_NAME_APPARMOR, enabled: false },
    Protected { name: XATTR_NAME_IMA, enabled: true },
    Protected { name: XATTR_NAME_CAPS, enabled: true },
];

/// Is this attribute covered by the EVM label? # C: O(n)
pub fn protected_xattr(name: &str) -> bool {
    PROTECTED.iter().any(|x| x.enabled && x.name == name)
}

/// Is this attribute covered by a portable label, which spans the whole
/// protected set regardless of local configuration? # C: O(n)
pub fn protected_xattr_any(name: &str) -> bool {
    PROTECTED.iter().any(|x| x.name == name)
}

/// Is this a POSIX access-control-list attribute? Writing one changes the mode,
/// which the label covers, so such writes are mediated even though the
/// attribute itself is not protected. # C: O(1)
pub fn posix_acl_xattr(name: &str) -> bool {
    name == "system.posix_acl_access" || name == "system.posix_acl_default"
}

/// Inode metadata the label covers.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct InodeAttrs {
    pub ino: u64,
    pub generation: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    /// Filesystem identifier, appended when the configuration includes it.
    pub fsuuid: [u8; 16],
}

/// Size of the metadata block: a 64-bit inode number, three 32-bit fields, a
/// 16-bit mode, and the pad that carries the block to its natural alignment.
pub const MISC_LEN: usize = 24;

/// Serialise the metadata block. A portable label omits the inode number and
/// generation, which are properties of one filesystem instance and would stop
/// the label verifying anywhere else. # C: O(1)
pub fn misc_block(a: &InodeAttrs, ty: XattrType) -> [u8; MISC_LEN] {
    let portable = ty == XattrType::EvmPortableDigsig;
    let mut b = [0u8; MISC_LEN];
    if !portable {
        b[0..8].copy_from_slice(&a.ino.to_le_bytes());
        b[8..12].copy_from_slice(&a.generation.to_le_bytes());
    }
    b[12..16].copy_from_slice(&a.uid.to_le_bytes());
    b[16..20].copy_from_slice(&a.gid.to_le_bytes());
    b[20..22].copy_from_slice(&a.mode.to_le_bytes());
    b
}

/// The bytes a label is computed over: each present protected attribute's
/// value in list order, then the metadata block, then the filesystem
/// identifier when the configuration includes it and the label is not
/// portable. `xattr_value(name)` supplies a value, or `None` when the inode
/// does not carry that attribute. # C: O(total)
pub fn label_input(
    ty: XattrType,
    attrs: &InodeAttrs,
    hmac_attrs: u32,
    mut xattr_value: impl FnMut(&str) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let portable = ty == XattrType::EvmPortableDigsig;
    let mut out = Vec::new();
    let mut any = false;
    let mut ima_present = false;
    for x in PROTECTED.iter() {
        if !portable && !x.enabled { continue; }
        if let Some(v) = xattr_value(x.name) {
            out.extend_from_slice(&v);
            any = true;
            if x.name == XATTR_NAME_IMA { ima_present = true; }
        }
    }
    // A label over no attributes at all is not a label.
    if !any { return None; }
    // A portable label must cover a file digest; without one it would attest
    // only to metadata and could be moved onto different contents.
    if portable && !ima_present { return None; }
    out.extend_from_slice(&misc_block(attrs, ty));
    if hmac_attrs & EVM_ATTR_FSUUID != 0 && !portable {
        out.extend_from_slice(&attrs.fsuuid);
    }
    Some(out)
}

/// Number of protected attributes the inode carries. # C: O(n)
pub fn count_protected(mut xattr_value: impl FnMut(&str) -> Option<Vec<u8>>) -> usize {
    PROTECTED.iter().filter(|x| x.enabled && xattr_value(x.name).is_some()).count()
}
