// The FID (`f_handle` payload) this kernel encodes, and its codec.
//
// A handle must survive the inode leaving the cache AND the inode NUMBER being
// reallocated to a different object, so the identity it carries is the pair
// `(ino, generation)` — never a bare inode number. `generation` is the inode's
// incarnation (this module); decode compares it and reports ESTALE on a
// mismatch, which is the whole reason a recycled number cannot be opened
// through a stale handle.
//
// A CONNECTABLE handle additionally carries the parent's `(ino, generation)`,
// because a decoded non-directory otherwise has no name and no parent and the
// reopened fd's path can never be rendered. Linux encodes a parent only for a
// non-directory: a directory has exactly one dentry, so decode reconnects it by
// walking `..` instead.
//
// Layout deliberately differs from Linux's `FILEID_INO32_GEN`, whose `ino` is a
// `u32`: this kernel's `vfs::Ino` is 64-bit (a backend tags the high half), so a
// 32-bit field would alias every tagged inode onto its untagged twin. The
// handle is opaque to userspace and only ever decoded by the kernel that minted
// it, so the widened field costs nothing. The TYPE numbers keep Linux's
// meaning: 1 = identity only, 2 = identity + parent.

use syscall::errno::Errno;

/// `handle_type` for `{ ino: u64, gen: u32 }`. Must be nonzero: type 0 means
/// "the filesystem root, no FID bytes".
pub const HANDLE_TYPE_INO_GEN: i32 = 1;
/// `handle_type` for `{ ino: u64, gen: u32, parent_ino: u64, parent_gen: u32 }`.
pub const HANDLE_TYPE_INO_GEN_PARENT: i32 = 2;

/// Encoded length of [`HANDLE_TYPE_INO_GEN`].
pub const FID_LEN: u32 = 12;
/// Encoded length of [`HANDLE_TYPE_INO_GEN_PARENT`].
pub const FID_LEN_PARENT: u32 = 24;

const OFF_INO: usize = 0;
const OFF_GEN: usize = 8;
const OFF_PARENT_INO: usize = 12;
const OFF_PARENT_GEN: usize = 20;

/// A decoded file identity: the object, and for a connectable handle the
/// directory it was named in when the handle was minted.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Fid {
    pub ino: u64,
    pub generation: u32,
    /// `(parent_ino, parent_generation)`, present only in a connectable
    /// non-directory handle.
    pub parent: Option<(u64, u32)>,
}

/// Payload length a `handle_type` claims, or `None` for a type this kernel did
/// not encode. A well-formed handle from a foreign encoder lands here and is
/// the caller's ESTALE, not EINVAL — it may simply describe an object this
/// filesystem no longer has.
/// # C: O(1)
pub fn fid_len_for_type(handle_type: i32) -> Option<u32> {
    match handle_type {
        HANDLE_TYPE_INO_GEN        => Some(FID_LEN),
        HANDLE_TYPE_INO_GEN_PARENT => Some(FID_LEN_PARENT),
        _                          => None,
    }
}

/// Bytes `name_to_handle_at` needs for this object. A connectable handle to a
/// DIRECTORY costs the plain size: Linux encodes no parent for a directory
/// because a directory has one dentry and decode reconnects it through `..`.
/// # C: O(1)
pub fn encoded_fid_len(connectable: bool, is_dir: bool) -> u32 {
    if connectable && !is_dir { FID_LEN_PARENT } else { FID_LEN }
}

/// Serialise `fid` little-endian into `buf`, returning `(bytes, handle_type)`.
/// `buf` must hold [`FID_LEN_PARENT`].
/// # C: O(1)
pub fn encode_fid(fid: &Fid, buf: &mut [u8; FID_LEN_PARENT as usize]) -> (u32, i32) {
    encode_fid_into(fid, buf)
}

/// [`encode_fid`] over a slice, for the `s_op->encode_fh` hook whose buffer is
/// sized by the filesystem's own [`encoded_fid_len`]. `buf` must hold
/// [`FID_LEN`], or [`FID_LEN_PARENT`] when `fid.parent` is set.
/// # C: O(1)
pub fn encode_fid_into(fid: &Fid, buf: &mut [u8]) -> (u32, i32) {
    buf[OFF_INO..OFF_INO + 8].copy_from_slice(&fid.ino.to_le_bytes());
    buf[OFF_GEN..OFF_GEN + 4].copy_from_slice(&fid.generation.to_le_bytes());
    match fid.parent {
        None => (FID_LEN, HANDLE_TYPE_INO_GEN),
        Some((pino, pgen)) => {
            buf[OFF_PARENT_INO..OFF_PARENT_INO + 8].copy_from_slice(&pino.to_le_bytes());
            buf[OFF_PARENT_GEN..OFF_PARENT_GEN + 4].copy_from_slice(&pgen.to_le_bytes());
            (FID_LEN_PARENT, HANDLE_TYPE_INO_GEN_PARENT)
        }
    }
}

/// Parse a FID payload. `handle_type` must already have had its user-flag bits
/// stripped ([`super::decode::strip_user_flags`], Linux does the same before
/// handing the handle to the filesystem).
///
/// ESTALE — not EINVAL — for a type this kernel does not encode or a payload
/// whose length disagrees with its type: both mean "undecodable here", and
/// Linux's answer for an undecodable-but-well-formed handle is staleness.
/// # C: O(1)
pub fn decode_fid(bytes: &[u8], handle_type: i32) -> Result<Fid, Errno> {
    let want = fid_len_for_type(handle_type).ok_or(Errno::Estale)?;
    if bytes.len() != want as usize { return Err(Errno::Estale); }
    let ino = u64::from_le_bytes(bytes[OFF_INO..OFF_INO + 8].try_into().map_err(|_| Errno::Estale)?);
    let generation =
        u32::from_le_bytes(bytes[OFF_GEN..OFF_GEN + 4].try_into().map_err(|_| Errno::Estale)?);
    let parent = if handle_type == HANDLE_TYPE_INO_GEN_PARENT {
        let pino = u64::from_le_bytes(
            bytes[OFF_PARENT_INO..OFF_PARENT_INO + 8].try_into().map_err(|_| Errno::Estale)?);
        let pgen = u32::from_le_bytes(
            bytes[OFF_PARENT_GEN..OFF_PARENT_GEN + 4].try_into().map_err(|_| Errno::Estale)?);
        Some((pino, pgen))
    } else { None };
    Ok(Fid { ino, generation, parent })
}
