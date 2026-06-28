//! `StaticFileInode` is a read-only pseudo file (fixed `&'static [u8]` body,
//! `write` → `EROFS`). Its reported mode must be `0o444` (`-r--r--r--`, like
//! Linux `/proc/version`), NOT the generic `Regular` fallback `0o644` which
//! advertises a phantom owner-write bit the inode can never honour. This pins
//! `perm()`/`i_mode()` consistent with the `EROFS` write path, plus the
//! body read semantics (offset clamp, partial read, EOF).

use vfs::inode::Inode;
use vfs::{FileType, StaticFileInode, VfsError};

const S_IFREG: u16 = 0o100000; // FileType::Regular S_IFMT bits (umode_t)

#[test]
fn static_file_is_read_only_0444() {
    let f = StaticFileInode::new(b"hello\n");
    assert_eq!(f.file_type(), FileType::Regular);
    assert_eq!(f.perm(), Some(0o444), "RO pseudo file reports r--r--r--, not the 0644 default");
    assert_eq!(f.i_mode(), S_IFREG | 0o444, "i_mode merges S_IFREG with the 0444 perm");
    // The mode must agree with the actual write behaviour: writes always fail.
    assert_eq!(f.write(0, b"x"), Err(VfsError::Erofs), "static body is unconditionally read-only");
}

#[test]
fn static_file_read_offset_and_eof() {
    let f = StaticFileInode::new(b"abcdef");
    assert_eq!(f.size(), 6);
    let mut buf = [0u8; 4];
    assert_eq!(f.read(0, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"abcd");
    // Read from an offset returns the tail, clamped to what's available.
    let mut tail = [0u8; 8];
    assert_eq!(f.read(4, &mut tail).unwrap(), 2, "offset 4 of a 6-byte body yields 2 bytes");
    assert_eq!(&tail[..2], b"ef");
    // At/after EOF → 0 (no error).
    assert_eq!(f.read(6, &mut tail).unwrap(), 0, "read at EOF returns 0");
    assert_eq!(f.read(99, &mut tail).unwrap(), 0, "read past EOF returns 0");
}

#[test]
fn distinct_static_files_get_distinct_inos() {
    let a = StaticFileInode::new(b"a");
    let b = StaticFileInode::new(b"b");
    assert_ne!(a.ino(), b.ino(), "each static file gets its own inode number");
}
