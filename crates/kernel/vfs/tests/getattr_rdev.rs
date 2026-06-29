//! inode-D4b (getattr part): `Kstat.st_rdev` carries the device number ONLY for
//! character/block device inodes, with the Linux `new_encode_dev` huge-dev
//! split (minor's low 8 bits + 12-bit major + minor's high bits in `[20..32)`),
//! and is 0 for every non-device inode — matching `generic_fillattr` (Linux
//! `fs/stat.c`), where `stat->rdev = inode->i_rdev` only resolves to a number on
//! device nodes. Driven over minimal `Inode` impls, no QEMU.
//!
//! The huge-dev split is the part the naive `(major<<8)|minor` legacy form gets
//! wrong: a minor ≥ 256 (dynamic char minors, loop/dm) would overflow into the
//! major field. `encode_dev` is the single canonical encoder every `rdev()`
//! impl must agree with, so this also pins `encode_dev == Devt::new(..).raw()`.

use vfs::getattr::encode_dev;
use vfs::{Devt, FileType, Inode, InodeBuilder, InodeRef, IDENTITY,
          default_file_ops, default_inode_ops, mk_mode};

/// Device node returning an already-encoded `dev_t` from `rdev()` (the Linux
/// contract: `i_rdev` is the packed number the driver model assigned).
fn dev_inode(ft: FileType, rdev: u32) -> InodeRef {
    InodeBuilder::new(3, mk_mode(ft, 0), default_inode_ops(), default_file_ops()).rdev(rdev).build()
}

/// Non-device inode that (incorrectly) carries a non-zero `i_rdev` — proves the
/// type gate, not the source, is what zeroes `st_rdev` off device nodes.
fn nondev_inode(ft: FileType) -> InodeRef {
    InodeBuilder::new(4, mk_mode(ft, 0), default_inode_ops(), default_file_ops()).rdev(0xdead).build()
}

fn fill_rdev(i: &Inode) -> u32 { vfs::generic_fillattr(i, &IDENTITY, None).rdev }

#[test]
fn encode_dev_matches_devt_and_splits_high_minor() {
    // Small numbers: huge form collapses to the legacy `(major<<8)|minor`.
    assert_eq!(encode_dev(1, 3), 0x0103, "mem/null 1:3");
    assert_eq!(encode_dev(1, 3), Devt::new(1, 3).raw(), "encode_dev == Devt::new");
    // Minor ≥ 256 must split: low 8 bits stay, the rest move to bits [20..32).
    let v = encode_dev(4, 300);                       // 300 = 0x12C
    assert_eq!(v & 0xff, 0x2c, "low 8 bits of minor in [0..8)");
    assert_eq!((v >> 8) & 0xfff, 4, "12-bit major in [8..20)");
    assert_eq!((v >> 20) & 0xfff, 1, "minor high bits (256) in [20..32)");
    assert_eq!(v, Devt::new(4, 300).raw(), "huge-minor encode == Devt::new");
    // And it round-trips back through Devt's decoders.
    let d = Devt::from_raw(v);
    assert_eq!((d.major(), d.minor()), (4, 300), "decode recovers major/minor");
}

#[test]
fn device_inodes_report_their_encoded_rdev() {
    let cdev = encode_dev(1, 3);
    let bdev = encode_dev(8, 0);                       // sd/sda 8:0
    assert_eq!(fill_rdev(&dev_inode(FileType::CharDev,  cdev)), cdev, "char rdev passed through");
    assert_eq!(fill_rdev(&dev_inode(FileType::BlockDev, bdev)), bdev, "block rdev passed through");
    // A high minor survives intact (no truncation in the fill path).
    let big = encode_dev(4, 300);
    assert_eq!(fill_rdev(&dev_inode(FileType::CharDev, big)), big, "high-minor char rdev intact");
}

#[test]
fn non_device_inodes_report_zero_rdev() {
    for ft in [FileType::Regular, FileType::Directory, FileType::Symlink,
               FileType::Fifo, FileType::Socket] {
        assert_eq!(fill_rdev(&nondev_inode(ft)), 0,
                   "non-device inode must zero st_rdev regardless of rdev()");
    }
}
