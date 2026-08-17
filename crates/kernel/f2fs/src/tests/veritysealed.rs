//! A sealed file, from the outside: what it refuses and what it still serves.
//!
//! The tree and the walk have their own tests. These are about the file
//! boundary — a verity inode is immutable, its stored size is its DATA size,
//! and the record that points at its descriptor is reachable only by index.

use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{BLKSIZE, XATTR_INDEX_USER, XATTR_INDEX_VERITY};
use crate::volume::{NewInode, Volume};
use alloc::vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 7);

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A writable volume holding one empty file, and that file's number.
fn with_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    (v, ino)
}

/// Every tree-block size the format admits, narrowest first.
///
/// The boundary behaviour below is stated in terms of the FILE's size, and at
/// every size but the widest one file block carries several attested blocks —
/// so the tree has a different shape, the descriptor a different position,
/// and the clamp a different amount of material behind it to hide.
const LOG_BS: core::ops::RangeInclusive<u8> = 10..=12;

/// Mark `ino` as attested by a hash tree over `log_bs`-sized blocks.
fn make_verity(v: &mut Volume<MemImage>, ino: u32, log_bs: u8) {
    // The real sealing path, not just the flag: a file carrying the flag with
    // no descriptor behind it is a corrupt inode, and a fixture that produced
    // one would be testing a state the filesystem never writes.
    v.enable_verity(ino, crate::verity::uapi::HASH_ALG_SHA256, log_bs, b"").unwrap();
}

#[test]
fn a_verity_file_refuses_a_write() {
    // Its contents are what its hash tree attests to; changing them would
    // leave the attestation describing bytes that are no longer there.
    for log_bs in LOG_BS {
        let (mut v, ino) = with_file();
        v.write_file(ino, 0, b"sealed").unwrap();
        make_verity(&mut v, ino, log_bs);
        assert!(v.read_inode(ino).unwrap().verity(), "log_bs {log_bs}");
        assert_eq!(v.write_file(ino, 0, b"x").err(), Some(Errno::Eperm), "log_bs {log_bs}");
    }
}

#[test]
fn a_verity_file_refuses_a_truncation() {
    for log_bs in LOG_BS {
        let (mut v, ino) = with_file();
        v.write_file(ino, 0, b"sealed").unwrap();
        make_verity(&mut v, ino, log_bs);
        assert_eq!(v.truncate_file(ino, 0).err(), Some(Errno::Eperm), "log_bs {log_bs}");
    }
}

#[test]
fn a_verity_files_data_still_reads() {
    for log_bs in LOG_BS {
        let (mut v, ino) = with_file();
        v.write_file(ino, 0, b"attested").unwrap();
        make_verity(&mut v, ino, log_bs);
        let inode = v.read_inode(ino).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(v.read_file(&inode, ino, 0, &mut buf).unwrap(), 8, "log_bs {log_bs}");
        assert_eq!(&buf, b"attested", "log_bs {log_bs}");
    }
}

#[test]
fn a_read_reaching_past_a_verity_files_data_is_refused() {
    // Past the stored size is where the hash tree and the descriptor live.
    // Serving them as file content is the concrete bug the clamp prevents,
    // and the material behind the clamp differs at every tree-block size.
    for log_bs in LOG_BS {
        let (mut v, ino) = with_file();
        v.write_file(ino, 0, &vec![7u8; 2 * BLKSIZE]).unwrap();
        make_verity(&mut v, ino, log_bs);
        let inode = v.read_inode(ino).unwrap();
        let mut buf = vec![0u8; 64];
        let past = inode.size - 8;
        assert_eq!(v.read_file(&inode, ino, past, &mut buf).err(), Some(Errno::Eio),
                   "log_bs {log_bs}");
        // A read that stays inside the data is unaffected.
        let mut small = [0u8; 8];
        assert_eq!(v.read_file(&inode, ino, past, &mut small).unwrap(), 8, "log_bs {log_bs}");
    }
}

#[test]
fn an_ordinary_file_is_not_clamped() {
    // The clamp must key on the flag, not on the size, or every short read
    // near the end of an ordinary file would fail.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &vec![7u8; 100]).unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert!(!inode.verity());
    let mut buf = vec![0u8; 64];
    assert_eq!(v.read_file(&inode, ino, 90, &mut buf).unwrap(), 10);
}

#[test]
fn the_verity_record_is_reachable_by_index_and_invisible_by_name() {
    // The format registers no prefix for it, so it must not appear in a
    // listing and no name a caller could pass may reach it.
    use crate::test_image::nodes::dir::add_file_with_xattrs;
    let mut b = test_image::with_root();
    let record = alloc::vec![9u8; crate::verity::uapi::LOCATION_SIZE];
    add_file_with_xattrs(
        &mut b,
        4,
        &[(XATTR_INDEX_VERITY, crate::verity::uapi::XATTR_NAME.to_vec(), record.clone()),
          (XATTR_INDEX_USER, b"seen".to_vec(), b"1".to_vec())],
        false,
    );
    let v = b.mount_rw().unwrap();
    let inode = v.read_inode(4).unwrap();
    assert_eq!(v.verity_attr(&inode, 4).unwrap(), record);
    assert_eq!(v.list_xattr(&inode, 4).unwrap(), b"user.seen\0".to_vec());
    assert_eq!(v.get_xattr(&inode, 4, "user.v").err(), Some(Errno::Enodata));
}

#[test]
fn a_file_with_no_verity_record_reports_no_data() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, b"plain").unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.verity_attr(&inode, ino).err(), Some(Errno::Enodata));
}
