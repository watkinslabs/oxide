// A `/dev/dri/*` inode is identified by the `DrmNodeData` it owns, never by
// its NUMBER. DRM inodes used to carry no backend state at all: `card_id` and
// primary-vs-render came out of arithmetic on `ino`, so any inode whose high
// 32 bits read `DRMC`/`DRMR` was accepted as a DRM node and drove event drain,
// poll, release, ioctl and dumb-buffer mmap against the card id decoded from a
// stranger's low bits.

use alloc::sync::Arc;
use vfs::pseudo_ino::{DRM_CARD, DRM_RENDER};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, File, FileType, Ino,
          InodeBuilder, InodeRef, OpenFlags};

use super::super::publication::{drm_inode_parts, make_card_inode, make_render_inode,
                                DrmNodeKind, DRM_CARD_INO, DRM_RENDER_INO};
use super::super::{handle_drm_ioctl, mmap_backing, pin_mmap_backing};
use crate::DRM_IOCTL_VERSION;

/// A card id high enough not to collide with a registered card.
const TEST_CARD: u32 = 0x7ef0;
/// Dumb-buffer mmap offset; any value, since no buffer is ever created here.
const ANY_MMAP_OFFSET: u64 = 0;

struct ForeignState;

/// An inode carrying `ino` and backend state that is not `DrmNodeData`.
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

fn open(inode: InodeRef) -> Arc<File> {
    let dentry = Dentry::new_anon(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR | OpenFlags::O_NONBLOCK)
}

#[test]
fn published_drm_numbers_fall_inside_their_declared_regions() {
    let _guard = crate::TEST_LOCK.lock();
    for card_id in [0u32, 7, TEST_CARD] {
        let card = make_card_inode(card_id).ino();
        let render = make_render_inode(card_id).ino();
        assert_eq!(card, DRM_CARD_INO | card_id as Ino);
        assert_eq!(render, DRM_RENDER_INO | card_id as Ino);
        assert!(DRM_CARD.contains(card), "{card:#x} outside {}", DRM_CARD.name());
        assert!(DRM_RENDER.contains(render), "{render:#x} outside {}", DRM_RENDER.name());
        assert!(!DRM_RENDER.contains(card));
        assert!(!DRM_CARD.contains(render));
    }
}

#[test]
fn a_real_drm_inode_resolves_to_its_own_minor_and_card() {
    let _guard = crate::TEST_LOCK.lock();
    assert_eq!(drm_inode_parts(&make_card_inode(TEST_CARD)),
        Some((DrmNodeKind::Card, TEST_CARD)));
    assert_eq!(drm_inode_parts(&make_render_inode(TEST_CARD)),
        Some((DrmNodeKind::Render, TEST_CARD)));
}

#[test]
fn a_foreign_inode_reusing_a_drm_number_is_declined() {
    let _guard = crate::TEST_LOCK.lock();
    for ino in [DRM_CARD_INO | TEST_CARD as Ino, DRM_RENDER_INO | TEST_CARD as Ino,
                DRM_CARD.start(), DRM_CARD.end(), DRM_RENDER.start()] {
        let stranger = foreign_inode(ino);
        assert_eq!(drm_inode_parts(&stranger), None, "{ino:#x}");
        assert_eq!(mmap_backing(&stranger, ANY_MMAP_OFFSET), None, "{ino:#x}");
        assert!(pin_mmap_backing(&stranger, ANY_MMAP_OFFSET).is_none(), "{ino:#x}");
        assert_eq!(handle_drm_ioctl(&open(stranger), DRM_IOCTL_VERSION, 0), None, "{ino:#x}");
    }
}

#[test]
fn an_inode_with_no_backend_state_is_declined() {
    let _guard = crate::TEST_LOCK.lock();
    let bare = bare_inode(DRM_CARD_INO | TEST_CARD as Ino);
    assert_eq!(drm_inode_parts(&bare), None);
    assert_eq!(mmap_backing(&bare, ANY_MMAP_OFFSET), None);
    assert_eq!(handle_drm_ioctl(&open(bare), DRM_IOCTL_VERSION, 0), None);
}

#[test]
fn a_render_inode_is_never_taken_for_a_card_inode() {
    // The primary/render split gated master-only and KMS ioctls, and it was
    // decided by the same arithmetic. Each node now states its own minor.
    let _guard = crate::TEST_LOCK.lock();
    let render = make_render_inode(TEST_CARD);
    assert_eq!(drm_inode_parts(&render), Some((DrmNodeKind::Render, TEST_CARD)));
    // `mmap_backing` and `pin_mmap_backing` are primary-node-only in Linux.
    assert_eq!(mmap_backing(&render, ANY_MMAP_OFFSET), None);
    assert!(pin_mmap_backing(&render, ANY_MMAP_OFFSET).is_none());
}
