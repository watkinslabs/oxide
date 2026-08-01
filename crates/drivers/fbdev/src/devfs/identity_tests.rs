// `/dev/fb<idx>` is identified by the `FbData` its inode owns, never by the
// inode NUMBER. The old test masked only the low 32 bits, so ANY inode whose
// low half read `0xFB00_xxxx` — a 64-bit tag family's number, an ext4 inode on
// a large filesystem — took every FBIO* ioctl and the mmap backing away from
// its real owner, then indexed the fb registry with the stranger's low bits.

use alloc::sync::Arc;
use vfs::pseudo_ino::FBDEV;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, Ino, InodeBuilder, InodeRef};

use super::{handle_fbdev_ioctl, make_fb_inode, mmap_backing, FB0_INO_BASE};

/// A framebuffer index high enough not to collide with a live scanout.
const TEST_FB_IDX: u32 = 0x7ff0;

struct ForeignState;

/// An inode carrying `ino` and backend state that is not `FbData`.
fn foreign_inode(ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0), default_inode_ops(), default_file_ops())
        .private(Arc::new(ForeignState))
        .build()
}

/// An inode carrying `ino` and no backend state at all.
fn bare_inode(ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0), default_inode_ops(), default_file_ops())
        .build()
}

#[test]
fn a_published_fb_number_falls_inside_the_fbdev_region() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let ino = make_fb_inode(TEST_FB_IDX).ino();
    assert_eq!(ino, FB0_INO_BASE | TEST_FB_IDX as Ino);
    assert!(FBDEV.contains(ino), "{ino:#x} outside {}", FBDEV.name());
    assert!(FBDEV.contains(make_fb_inode(0).ino()));
}

#[test]
fn a_real_fb_inode_resolves_to_its_own_index() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let inode = make_fb_inode(TEST_FB_IDX);
    assert_eq!(super::fb_index_of(&inode), Some(TEST_FB_IDX));
    assert_eq!(super::fb_index_of(&make_fb_inode(0)), Some(0));
}

#[test]
fn a_foreign_inode_reusing_an_fb_number_is_declined() {
    let _fbdev = crate::test_claim::claim_fbdev();
    // The exact number `/dev/fb0` carries, on an inode that is not a
    // framebuffer. Resolving it would run the FBIO* body against fb 0.
    let stranger = foreign_inode(FB0_INO_BASE);
    assert_eq!(super::fb_index_of(&stranger), None);
    assert_eq!(handle_fbdev_ioctl(&stranger, crate::FBIOGET_VSCREENINFO, 0), None);
    assert_eq!(handle_fbdev_ioctl(&stranger, crate::FBIOBLANK, crate::FB_BLANK_NORMAL as u64), None);
    assert_eq!(mmap_backing(&stranger), None);
}

#[test]
fn an_inode_with_no_backend_state_is_declined() {
    let _fbdev = crate::test_claim::claim_fbdev();
    let bare = bare_inode(FB0_INO_BASE | TEST_FB_IDX as Ino);
    assert_eq!(super::fb_index_of(&bare), None);
    assert_eq!(handle_fbdev_ioctl(&bare, crate::FBIOGET_FSCREENINFO, 0), None);
    assert_eq!(mmap_backing(&bare), None);
}

#[test]
fn a_high_inode_whose_low_half_reads_as_fbdev_is_declined() {
    let _fbdev = crate::test_claim::claim_fbdev();
    // What the low-32-bit mask could not see: every tag family mints numbers
    // whose low 32 bits are its own id, so an ext4 inode number or a socket id
    // of 0xFB00_0003 produced a full match and stole fb 3's ioctls.
    const FOREIGN_TAG: Ino = 0x6E54_0000 << 32;
    let ino = FOREIGN_TAG | FB0_INO_BASE | 3;
    assert!(!FBDEV.contains(ino));
    let stranger = foreign_inode(ino);
    assert_eq!(super::fb_index_of(&stranger), None);
    assert_eq!(handle_fbdev_ioctl(&stranger, crate::FBIOGET_VSCREENINFO, 0), None);
    assert_eq!(mmap_backing(&stranger), None);
}
