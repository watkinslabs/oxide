//! The two pure decisions the mutating adapter owns.

use super::*;
use crate::mode;

#[test]
fn a_mode_word_carries_the_type_and_the_permission_bits() {
    let m = mk_mode(FileType::Regular, 0o644);
    assert_eq!(m & mode::S_IFMT, mode::S_IFREG);
    assert_eq!(mode::perm(m), 0o644);
}

#[test]
fn every_type_gets_its_own_field() {
    for (ft, want) in [
        (FileType::Regular, mode::S_IFREG),
        (FileType::Directory, mode::S_IFDIR),
        (FileType::Symlink, mode::S_IFLNK),
        (FileType::CharDev, mode::S_IFCHR),
        (FileType::BlockDev, mode::S_IFBLK),
        (FileType::Fifo, mode::S_IFIFO),
        (FileType::Socket, mode::S_IFSOCK),
    ] {
        assert_eq!(mk_mode(ft, 0o600) & mode::S_IFMT, want);
        assert_eq!(mode::file_type(mk_mode(ft, 0o600)), ft);
    }
}

#[test]
fn permission_bits_past_the_field_are_dropped() {
    // A caller's mode may carry the type too; taking it whole would set a
    // second type field into the permission bits.
    let m = mk_mode(FileType::Regular, 0o170_644);
    assert_eq!(m & mode::S_IFMT, mode::S_IFREG);
    assert_eq!(mode::perm(m), 0o644);
}

#[test]
fn the_set_id_and_sticky_bits_survive() {
    assert_eq!(mode::perm(mk_mode(FileType::Regular, 0o4755)), 0o4755);
    assert_eq!(mode::perm(mk_mode(FileType::Directory, 0o1777)), 0o1777);
}

#[test]
fn a_node_with_no_type_field_is_a_regular_file() {
    // What `mknod(2)` creates for a zero type.
    assert_eq!(mknod_type(0o644).unwrap(), FileType::Regular);
}

#[test]
fn the_four_special_kinds_are_what_a_node_may_be() {
    for (m, want) in [
        (mode::S_IFCHR, FileType::CharDev),
        (mode::S_IFBLK, FileType::BlockDev),
        (mode::S_IFIFO, FileType::Fifo),
        (mode::S_IFSOCK, FileType::Socket),
        (mode::S_IFREG, FileType::Regular),
    ] {
        assert_eq!(mknod_type(u32::from(m) | 0o600).unwrap(), want);
    }
}

#[test]
fn a_node_may_not_be_a_directory_or_a_link() {
    // Those have their own operations, which set up contents this one does
    // not; making one here would leave a directory with no entries at all.
    assert_eq!(mknod_type(u32::from(mode::S_IFDIR) | 0o755).err(), Some(VfsError::Einval));
    assert_eq!(mknod_type(u32::from(mode::S_IFLNK) | 0o777).err(), Some(VfsError::Einval));
}
