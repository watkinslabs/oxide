//! The range each valued option's argument must fall in.
//!
//! A value outside its range is refused at the mount rather than clamped,
//! because every one of these numbers describes a layout: an inline attribute
//! reservation wider than the address array overlays the addresses, and a log
//! count the checkpoint has no current-segment slot for describes logs the
//! volume does not have. Clamping would leave the mount running against a
//! shape neither the caller nor the medium agreed to.

use crate::uapi::{DEF_ADDRS_PER_INODE, INLINE_RESERVED_SIZE, TOTAL_EXTRA_ATTR_SIZE,
                  XATTR_HEADER_SIZE};

/// Log counts the format admits. Anything else would leave the checkpoint's
/// current-segment array describing logs the volume does not have.
pub const VALID_ACTIVE_LOGS: [u32; 3] = [2, 4, 6];

/// Bytes an inline directory needs before it holds anything of its own: the
/// two entries every directory has.
const MIN_INLINE_DENTRY_BYTES: usize = 40;

/// Narrowest inline attribute reservation, in addresses. Below this the region
/// cannot hold even its own header, so nothing could ever be stored inline.
pub const MIN_INLINE_XATTR: u32 = (XATTR_HEADER_SIZE / 4) as u32;

/// Widest inline attribute reservation, in addresses.
///
/// What is left of the address array once the extra-attribute region at its
/// head, the reserved address, and the space a directory needs for its own two
/// entries are taken out. A reservation past this overlays one of the three.
pub const MAX_INLINE_XATTR: u32 = (DEF_ADDRS_PER_INODE
    - TOTAL_EXTRA_ATTR_SIZE / 4
    - INLINE_RESERVED_SIZE
    - MIN_INLINE_DENTRY_BYTES / 4) as u32;

/// Widest percentage a checkpoint-disabled cap may name.
pub const MAX_UNUSABLE_PERC: u32 = 100;

/// Whether `n` is a log count the volume can carry. # C: O(1)
pub fn active_logs_ok(n: u32) -> bool { VALID_ACTIVE_LOGS.contains(&n) }

/// Whether `n` addresses can be reserved for inline attributes. # C: O(1)
pub fn inline_xattr_ok(n: u32) -> bool { (MIN_INLINE_XATTR..=MAX_INLINE_XATTR).contains(&n) }
