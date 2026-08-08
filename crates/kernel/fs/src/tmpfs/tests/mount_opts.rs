// Mount-level end of the option contract: what an option string does to the
// filesystem it mounts, not just to the parse result.

use alloc::string::String;
use vfs::FileType;

use super::super::TmpfsFs;
use super::super::accounting::TmpfsSb;
use super::super::inode::constrain_ino;
use super::super::mount_opts::{MountCred, parse_opts};

#[test]
fn from_mount_data_sets_root_owner_and_mode() {
    let fs = TmpfsFs::from_mount_data(
        String::from("/run/user/979"),
        "mode=0700,uid=979,gid=979,size=402886656,nr_inodes=819200",
    ).expect("the runtime-dir option string mounts");
    let root = fs.root_inode();
    assert_eq!(root.file_type(), FileType::Directory);
    assert_eq!(root.perm(), Some(0o700));
    assert_eq!(root.uid(), Some(979));
    assert_eq!(root.gid(), Some(979));
}

#[test]
fn from_mount_data_default_is_root_owned_0755() {
    let fs = TmpfsFs::from_mount_data(String::from("/tmp"), "").expect("no options mounts");
    let root = fs.root_inode();
    assert_eq!(root.perm(), Some(0o755));
    assert_eq!((root.uid(), root.gid()), (Some(0), Some(0)));
}

/// An option the filesystem cannot honour fails the MOUNT, not just the parse.
/// Before this the mount succeeded and the option vanished.
#[test]
fn an_option_that_cannot_be_honoured_fails_the_mount() {
    assert!(TmpfsFs::from_mount_data(String::from("/tmp"), "size=64mb").is_err());
    assert!(TmpfsFs::from_mount_data(String::from("/tmp"), "huge=always").is_err());
    assert!(TmpfsFs::from_mount_data(String::from("/tmp"), "casefold=latin1").is_err());
    // ramfs takes `mode=` and nothing else, but a key it shares must still work.
    assert!(TmpfsFs::ramfs_from_mount_data("mode=0755").is_ok());
    assert!(TmpfsFs::ramfs_from_mount_data("strict_encoding").is_err());
}

/// `noswap` reaches the one place that decides whether a page may be written
/// to swap. A mount without it still may; a mount with it never does.
#[test]
fn noswap_reaches_the_swap_decision() {
    let plain = TmpfsSb::from_opts(&parse_opts("", 0, MountCred::KERNEL).unwrap());
    assert!(plain.may_swap_out(), "an ordinary mount swaps");
    let never = TmpfsSb::from_opts(&parse_opts("noswap", 0, MountCred::KERNEL).unwrap());
    assert!(!never.may_swap_out(), "a noswap mount does not");
}

/// `inode32`/`inode64` reach the inode-number allocator. Without `inode64` a
/// number that has outgrown 32 bits is folded back into range, because a
/// 32-bit `stat(2)` on a file whose number does not fit answers EOVERFLOW
/// instead of answering.
#[test]
fn the_inode_number_width_reaches_the_allocator() {
    let raw = (u32::MAX as u64) + 1;
    let narrow = constrain_ino(raw, false);
    assert!(narrow <= u32::MAX as u64, "inode32 numbers stay 32-bit representable");
    assert!(vfs::pseudo_ino::TMPFS.contains(narrow), "and stay in tmpfs's own range");
    assert_eq!(constrain_ino(raw, true), raw, "inode64 numbers pass through");
    // Zero is the "no inode" sentinel and is never handed out either way.
    assert_ne!(constrain_ino(0, true), 0);
    assert_ne!(constrain_ino(0, false), 0);

    let wide = TmpfsSb::from_opts(&parse_opts("inode64", 0, MountCred::KERNEL).unwrap());
    assert!(wide.full_inums());
    let narrow_sb = TmpfsSb::from_opts(&parse_opts("inode32", 0, MountCred::KERNEL).unwrap());
    assert!(!narrow_sb.full_inums());
    // Whatever the width, an allocated number is never the sentinel.
    assert_ne!(wide.alloc_ino(), 0);
    assert_ne!(narrow_sb.alloc_ino(), 0);
}

/// The ceilings land on the accounting `statfs(2)` reports.
#[test]
fn the_size_and_inode_ceilings_land_on_the_superblock() {
    let sb = TmpfsSb::from_opts(&parse_opts("nr_blocks=64,nr_inodes=8", 0, MountCred::KERNEL).unwrap());
    let st = sb.statfs(super::super::uapi::TMPFS_MAGIC);
    assert_eq!((st.f_blocks, st.f_files), (64, 8));
}
