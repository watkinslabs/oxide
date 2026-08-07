use alloc::string::String;
use vfs::FileType;

use super::super::TmpfsFs;
use super::super::limits::PG;
use super::super::mount_opts::{SizeVal, TmpfsOpts};

#[test]
fn parses_systemd_run_user_string() {
    let data = "mode=0700,uid=979,gid=979,size=402886656,nr_inodes=819200";
    let o = TmpfsOpts::parse(data, 0);
    assert_eq!(o.mode, Some(0o700));
    assert_eq!(o.uid, Some(979));
    assert_eq!(o.gid, Some(979));
    assert_eq!(o.size_bytes, Some(402_886_656));
    assert_eq!(o.nr_inodes, Some(819_200));
    assert_eq!(o.resolve_blocks(1 << 20), 402_886_656 / PG as u64);
    assert_eq!(o.resolve_inodes(1 << 20), 819_200);
}

#[test]
fn size_rounds_up_and_unknown_keys_are_ignored() {
    let o = TmpfsOpts::parse("size=4097,noswap,smackfsroot=*,mode=1777", 0);
    assert_eq!(o.size_bytes, Some(4097));
    assert_eq!(o.resolve_blocks(999), 2);
    assert_eq!(o.mode, Some(0o1777));
    assert_eq!(o.resolve_inodes(555), 555);
}

#[test]
fn size_suffixes_and_percent_are_page_granular() {
    assert_eq!(TmpfsOpts::parse("size=64m", 0).size_bytes, Some(64 << 20));
    assert_eq!(TmpfsOpts::parse("size=2g", 0).size_bytes, Some(2u64 << 30));
    let o = TmpfsOpts::parse("size=50%", 1000);
    assert_eq!(o.size_bytes, Some(500 * PG as u64));
    assert_eq!(o.resolve_blocks(1), 500);
    let _ = SizeVal::Bytes(0);
}

#[test]
fn last_block_limit_option_wins() {
    assert_eq!(TmpfsOpts::parse("size=4096,nr_blocks=7", 0).resolve_blocks(99), 7);
    assert_eq!(TmpfsOpts::parse("nr_blocks=7,size=8193", 0).resolve_blocks(99), 3);
}

#[test]
fn empty_data_uses_defaults() {
    let o = TmpfsOpts::parse("", 0);
    assert_eq!((o.mode, o.uid, o.gid), (None, None, None));
    assert_eq!(o.resolve_blocks(1234), 1234);
    assert_eq!(o.resolve_inodes(1234), 1234);
}

#[test]
fn from_mount_data_sets_root_owner_and_mode() {
    let fs = TmpfsFs::from_mount_data(
        String::from("/run/user/979"),
        "mode=0700,uid=979,gid=979,size=402886656,nr_inodes=819200",
    );
    let root = fs.root_inode();
    assert_eq!(root.file_type(), FileType::Directory);
    assert_eq!(root.perm(), Some(0o700));
    assert_eq!(root.uid(), Some(979));
    assert_eq!(root.gid(), Some(979));
}

#[test]
fn from_mount_data_default_is_root_owned_0755() {
    let fs = TmpfsFs::from_mount_data(String::from("/tmp"), "");
    let root = fs.root_inode();
    assert_eq!(root.perm(), Some(0o755));
    assert_eq!((root.uid(), root.gid()), (Some(0), Some(0)));
}
