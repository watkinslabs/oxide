//! The two pure decisions the operations layer owns.
//!
//! Everything else in that module reaches the block layer through a mounted
//! filesystem and is exercised by the volume suite; these two are the ones
//! that would otherwise have no check at all.

use super::*;

#[test]
fn each_stored_type_byte_maps_to_its_own_kind() {
    assert_eq!(vfs_type(FT_REG_FILE), FileType::Regular);
    assert_eq!(vfs_type(FT_DIR), FileType::Directory);
    assert_eq!(vfs_type(FT_CHRDEV), FileType::CharDev);
    assert_eq!(vfs_type(FT_BLKDEV), FileType::BlockDev);
    assert_eq!(vfs_type(FT_FIFO), FileType::Fifo);
    assert_eq!(vfs_type(FT_SOCK), FileType::Socket);
    assert_eq!(vfs_type(FT_SYMLINK), FileType::Symlink);
}

#[test]
fn an_unknown_type_byte_presents_as_a_regular_file_rather_than_vanishing() {
    // The entry exists; hiding it would make the name unreachable, and the
    // inode it points at states its own real type.
    assert_eq!(vfs_type(FT_UNKNOWN), FileType::Regular);
    assert_eq!(vfs_type(FT_MAX), FileType::Regular);
    assert_eq!(vfs_type(200), FileType::Regular);
}

#[test]
fn a_zero_terminated_name_list_splits_into_its_names() {
    assert_eq!(split_names(b"user.a\0trusted.b\0"), ["user.a", "trusted.b"]);
}

#[test]
fn an_empty_list_splits_into_nothing() {
    assert!(split_names(b"").is_empty());
    assert!(split_names(b"\0").is_empty());
}

#[test]
fn a_list_without_a_trailing_terminator_still_yields_its_last_name() {
    assert_eq!(split_names(b"user.a\0user.b"), ["user.a", "user.b"]);
}

#[test]
fn a_repeated_terminator_does_not_produce_an_empty_name() {
    assert_eq!(split_names(b"a\0\0b\0"), ["a", "b"]);
}

#[test]
fn a_name_with_bytes_no_encoder_should_have_produced_is_shown_rather_than_dropped() {
    let out = split_names(&[0xFF, b'x', 0]);
    assert_eq!(out.len(), 1);
    assert!(out[0].ends_with('x'));
}

#[test]
fn the_registry_facing_surface_has_the_shape_the_registry_expects() {
    // A compile-time check that the names and signatures the mount registry
    // binds against are the ones this crate exports; a rename here would
    // otherwise only show up in another crate's build.
    type Ctor = fn(alloc::sync::Arc<dyn block::BlockDevice>, &str, bool, crate::Options)
        -> vfs::KResult<alloc::sync::Arc<crate::F2fs>>;
    let _: Ctor = crate::F2fs::open_with;
    let _: fn(crate::Options, &str) -> Result<crate::Options, syscall::errno::Errno> =
        crate::opts::parse;
    let _: fn(&crate::Options) -> String = crate::opts::show;
    let _: fn(syscall::errno::Errno) -> vfs::VfsError = crate::errno_to_vfs;
    let _: fn(&crate::F2fs) -> bool = crate::F2fs::is_writable;
    assert_eq!(crate::F2FS_SUPER_MAGIC, 0xF2F5_2010);
    assert_eq!(crate::F2FS_NAME, "f2fs");
}
