/// High-32 marker baked into every ext4 VFS `ino()`:
/// `EXT4_INO_MARK | (ext4_ino as u64)`. Lets `close_hook` / `linkat` /
/// `265_linkat.rs` recognise an ext4-resident inode without a mount
/// handle. The marker occupies the HIGH 32 bits so the LOW 32 bits hold
/// a FULL ext4 inode number (real ext4 images have inos far above 2^16).
/// Per-mount disambiguation is via the wrapper's own `RootfsState` (not
/// the marker), so two mounts can share marker bits. The high-32 value
/// `0x6E54_0000` (`"nT"` + zero) does not collide with SOCK/PERF/UFFD/
/// NLSK/IOUR/LND inode tags.
pub const EXT4_INO_MARK: u64 = 0x6E54_0000_0000_0000;
/// Mask selecting the high-32 marker bits in a VFS ino.
pub const EXT4_INO_MASK: u64 = 0xFFFF_FFFF_0000_0000;

/// Encode an ext4 inode number into a VFS ino (marker | full 32-bit ino).
/// # C: O(1)
#[inline]
pub const fn ext4_wrap_ino(ino: u32) -> vfs::Ino { EXT4_INO_MARK | (ino as u64) }

/// True iff `vfs_ino` carries the ext4 high-32 marker.
/// # C: O(1)
#[inline]
pub const fn is_ext4_ino(vfs_ino: u64) -> bool { (vfs_ino & EXT4_INO_MASK) == EXT4_INO_MARK }

/// Recover the full 32-bit ext4 inode number from a marked VFS ino.
/// Caller must have verified `is_ext4_ino` first.
/// # C: O(1)
#[inline]
pub const fn ext4_unwrap_ino(vfs_ino: u64) -> u32 { (vfs_ino & !EXT4_INO_MASK) as u32 }
