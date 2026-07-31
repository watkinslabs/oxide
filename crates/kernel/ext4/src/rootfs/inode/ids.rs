/// High-32 marker baked into every ext4 VFS `ino()`:
/// `EXT4_INO_MARK | (ext4_ino as u64)`. Lets `close_hook` / `linkat` /
/// `265_linkat.rs` recognise an ext4-resident inode without a mount
/// handle. The marker occupies the HIGH 32 bits so the LOW 32 bits hold
/// a FULL ext4 inode number (real ext4 images have inos far above 2^16).
/// Per-mount disambiguation is via the wrapper's own `RootfsState` (not
/// the marker), so two mounts can share marker bits. The marker comes from
/// `vfs::pseudo_ino`, whose const overlap check proves it collides with no
/// other owner — a hand-maintained list of the tags it "does not collide
/// with" cannot, and had already fallen behind the owners it names.
pub const EXT4_INO_MARK: u64 = vfs::pseudo_ino::EXT4.start();
/// Mask selecting the high-32 marker bits in a VFS ino.
pub const EXT4_INO_MASK: u64 = !(vfs::pseudo_ino::EXT4.end() - vfs::pseudo_ino::EXT4.start());

/// Encode an ext4 inode number into a VFS ino (marker | full 32-bit ino).
/// # C: O(1)
#[inline]
pub const fn ext4_wrap_ino(ino: u32) -> vfs::Ino { EXT4_INO_MARK | (ino as u64) }

/// True iff `vfs_ino` carries the ext4 high-32 marker. A number test is sound
/// HERE and nowhere else in this tree: the low 32 bits hold a real on-disk
/// inode number, so ext4 owns the whole tag and nothing else can mint into it
/// — which is the property `vfs::pseudo_ino`'s overlap assertion proves.
/// # C: O(1)
#[inline]
pub const fn is_ext4_ino(vfs_ino: u64) -> bool { (vfs_ino & EXT4_INO_MASK) == EXT4_INO_MARK }

/// Recover the full 32-bit ext4 inode number from a marked VFS ino.
/// Caller must have verified `is_ext4_ino` first.
/// # C: O(1)
#[inline]
pub const fn ext4_unwrap_ino(vfs_ino: u64) -> u32 { (vfs_ino & !EXT4_INO_MASK) as u32 }

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::pseudo_ino::{Region, EXT4, REGIONS};

    /// The marker is the registry's, so the "does not collide with" guarantee
    /// is checked by the const overlap assertion rather than by a comment that
    /// has to be kept current by hand.
    #[test]
    fn the_marker_is_the_registry_region() {
        assert_eq!(EXT4_INO_MARK, EXT4.start());
        assert_eq!(EXT4_INO_MASK, 0xFFFF_FFFF_0000_0000);
        assert_eq!(EXT4.len(), 1u64 << 32, "ext4 owns a full 32-bit ino space");
    }

    /// A number test is sound for ext4 alone: nothing else can mint into the
    /// tag, which is what makes `is_ext4_ino` an ownership answer here and
    /// nowhere else.
    #[test]
    fn no_other_owner_can_mint_an_ext4_number() {
        let disjoint = |r: &Region| r.start() == EXT4.start() || !vfs::pseudo_ino::overlaps(r, &EXT4);
        for r in REGIONS { assert!(disjoint(r), "{} overlaps the ext4 tag", r.name()); }
    }

    /// Round-trip: every ext4 inode number is recognised and recovered whole.
    #[test]
    fn every_ext4_inode_number_round_trips() {
        for ino in [1u32, 2, 11, 0xFFFF, 0x0001_0000, u32::MAX] {
            let wrapped = ext4_wrap_ino(ino);
            assert!(is_ext4_ino(wrapped));
            assert!(EXT4.contains(wrapped));
            assert_eq!(ext4_unwrap_ino(wrapped), ino);
        }
    }

    /// Numbers no other owner minted are not ext4's.
    #[test]
    fn another_owners_number_is_not_an_ext4_number() {
        for r in REGIONS {
            if r.start() == EXT4.start() { continue; }
            assert!(!is_ext4_ino(r.start()), "{} start read as an ext4 ino", r.name());
        }
    }
}
