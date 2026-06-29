//! superblock-D1/D16/D19 (`s_flags` + `SB_*` predicate surface): a `SuperBlock`
//! carries the Linux `super_block.s_flags` mount/option bitmask with the full
//! `SB_*` constant set and the `sb_rdonly`-style named predicates that the inode
//! `IS_NOSUID`/`IS_NODEV`/`IS_SYNC`/… helpers consult. A fresh `for_backend` SB
//! starts `SB_ACTIVE | SB_BORN`; `set_s_flags` flips arbitrary bits without
//! rebuilding the SB; `generic_shutdown_super` clears `SB_ACTIVE` at teardown.
//! Before the predicate surface landed, only `is_readonly`/`set_readonly`
//! existed — a caller could not ask whether a mount was nosuid/nodev/sync/etc.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::superblock::{
    next_anon_dev, SB_ACTIVE, SB_BORN, SB_DIRSYNC, SB_I_VERSION, SB_KERNMOUNT, SB_LAZYTIME,
    SB_MANDLOCK, SB_NOATIME, SB_NODEV, SB_NODIRATIME, SB_NOEXEC, SB_NOSUID, SB_POSIXACL,
    SB_RDONLY, SB_SYNCHRONOUS,
};
use vfs::SuperBlock;

struct FFs;
impl FileSystem for FFs {
    fn name(&self) -> &str { "ffs" }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(FFs), None, next_anon_dev(), String::from("ffs"))
}

#[test]
fn fresh_sb_is_born_and_mounted() {
    let sb = sb();
    assert!(sb.is_born(), "fill_super sets SB_BORN");
    assert!(sb.is_mounted(), "a mounted instance has SB_ACTIVE");
    assert!(!sb.is_readonly(), "default mount is rw");
    // None of the option bits set by default.
    assert!(!sb.is_nosuid() && !sb.is_nodev() && !sb.is_noexec());
    assert!(!sb.is_synchronous() && !sb.is_dirsync() && !sb.is_mandlock());
    assert!(!sb.is_noatime() && !sb.is_nodiratime());
    assert!(!sb.is_posixacl() && !sb.is_i_version() && !sb.is_lazytime() && !sb.is_kernmount());
}

#[test]
fn named_predicates_track_each_flag() {
    // Each predicate reads exactly its own bit — set one, only it flips.
    let cases: &[(u64, fn(&SuperBlock) -> bool)] = &[
        (SB_RDONLY,      SuperBlock::is_readonly),
        (SB_NOSUID,      SuperBlock::is_nosuid),
        (SB_NODEV,       SuperBlock::is_nodev),
        (SB_NOEXEC,      SuperBlock::is_noexec),
        (SB_SYNCHRONOUS, SuperBlock::is_synchronous),
        (SB_MANDLOCK,    SuperBlock::is_mandlock),
        (SB_DIRSYNC,     SuperBlock::is_dirsync),
        (SB_NOATIME,     SuperBlock::is_noatime),
        (SB_NODIRATIME,  SuperBlock::is_nodiratime),
        (SB_POSIXACL,    SuperBlock::is_posixacl),
        (SB_I_VERSION,   SuperBlock::is_i_version),
        (SB_LAZYTIME,    SuperBlock::is_lazytime),
        (SB_KERNMOUNT,   SuperBlock::is_kernmount),
    ];
    for &(bit, pred) in cases {
        let sb = sb();
        assert!(!pred(&sb), "predicate is false before the bit is set");
        sb.set_s_flags(bit, 0);
        assert!(pred(&sb), "predicate true after set_s_flags sets its bit");
        assert!(sb.sb_has_flag(bit), "generic sb_has_flag agrees");
        // Setting one option bit must not have disturbed the lifecycle bits.
        assert!(sb.is_born() && sb.is_mounted(), "lifecycle bits untouched");
        sb.set_s_flags(0, bit);
        assert!(!pred(&sb), "predicate false again after clearing the bit");
    }
}

#[test]
fn sb_rdonly_alias_matches_is_readonly() {
    let sb = sb();
    assert_eq!(sb.sb_rdonly(), sb.is_readonly());
    sb.set_readonly(true);
    assert!(sb.sb_rdonly() && sb.is_readonly(), "RO toggle visible via both names");
    sb.set_readonly(false);
    assert!(!sb.sb_rdonly() && !sb.is_readonly());
}

#[test]
fn shutdown_clears_active_flag_keeps_born() {
    let sb = sb();
    assert!(sb.is_mounted());
    // generic_shutdown_super (driven by the last deactivate_super) clears SB_ACTIVE.
    assert!(sb.deactivate_super(), "single active ref → last drop runs shutdown");
    assert!(!sb.is_mounted(), "SB_ACTIVE cleared once the instance is torn down");
    assert!(sb.is_born(), "SB_BORN is not cleared by shutdown");
}

#[test]
fn flag_constants_match_linux_values() {
    // Linux include/linux/fs.h numeric values (MS_*/SB_* one-to-one in low bits).
    assert_eq!(SB_RDONLY, 1);
    assert_eq!(SB_NOSUID, 2);
    assert_eq!(SB_NODEV, 4);
    assert_eq!(SB_NOEXEC, 8);
    assert_eq!(SB_SYNCHRONOUS, 16);
    assert_eq!(SB_MANDLOCK, 64);
    assert_eq!(SB_DIRSYNC, 128);
    assert_eq!(SB_NOATIME, 1024);
    assert_eq!(SB_NODIRATIME, 2048);
    assert_eq!(SB_SYNCHRONOUS | SB_RDONLY, 17);
    assert_eq!(SB_ACTIVE, 1 << 30);
    assert_eq!(SB_BORN, 1 << 29);
    assert_eq!(SB_POSIXACL, 1 << 16);
    assert_eq!(SB_KERNMOUNT, 1 << 22);
    assert_eq!(SB_I_VERSION, 1 << 23);
    assert_eq!(SB_LAZYTIME, 1 << 25);
}
