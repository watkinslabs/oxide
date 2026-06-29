//! `File::read_iter` / `File::write_iter` — vectored I/O (readv(2)/writev(2)
//! core, Linux `do_iter_read`/`do_iter_write`): aggregate a slice of buffers
//! into ONE cursor-advancing op, advancing `f_pos` ONCE under `f_pos_lock`,
//! with correct short-read/partial semantics and total-byte return.
//!
//! Before this change `File` exposed only scalar `read`/`write`; vectored I/O
//! was emulated at the syscall layer by calling scalar `read`/`write` once per
//! iovec, taking `f_pos_lock` separately each time (the cursor could interleave
//! between buffers on a shared fd). These assertions did not compile.

use std::sync::{Arc, Mutex};

use vfs::{Dentry, File, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, OpenFlags,
          VfsError, default_inode_ops, mk_mode};

/// Backend state for the regular-file inode: a growable byte vector honoring the
/// explicit offset, so cursor advancement across vectored buffers is observable.
struct MemData(Mutex<Vec<u8>>);

/// `f_op` reading/writing the inode's `i_private` byte vector.
struct MemFileOps;
impl FileOps for MemFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<MemData>().unwrap().0.lock().unwrap();
        let off = off as usize;
        if off >= d.len() { return Ok(0); }
        let n = core::cmp::min(buf.len(), d.len() - off);
        buf[..n].copy_from_slice(&d[off..off + n]);
        Ok(n)
    }
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let mut d = inode.private::<MemData>().unwrap().0.lock().unwrap();
        let off = off as usize;
        if off + buf.len() > d.len() { d.resize(off + buf.len(), 0); }
        d[off..off + buf.len()].copy_from_slice(buf);
        inode.set_size(d.len() as u64);
        Ok(buf.len())
    }
}

fn mem_file(init: &[u8], flags: OpenFlags) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x7ec, mk_mode(FileType::Regular, 0o644),
            default_inode_ops(), Arc::new(MemFileOps))
        .size(init.len() as u64)
        .private(Arc::new(MemData(Mutex::new(init.to_vec()))))
        .build();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

#[test]
fn read_iter_fills_buffers_in_order_and_advances_once() {
    let f = mem_file(b"ABCDEFGHIJ", OpenFlags::O_RDONLY);
    let (mut a, mut b, mut c) = ([0u8; 3], [0u8; 4], [0u8; 2]);
    let total = {
        let mut iov: [&mut [u8]; 3] = [&mut a, &mut b, &mut c];
        f.read_iter(&mut iov).unwrap()
    };
    assert_eq!(total, 9);
    assert_eq!(&a, b"ABC");
    assert_eq!(&b, b"DEFG");
    assert_eq!(&c, b"HI");
    // f_pos advanced exactly ONCE by the grand total.
    assert_eq!(f.pos(), 9);
}

#[test]
fn read_iter_short_at_eof_stops_and_reports_partial() {
    // Only 5 bytes available; second buffer is short-filled, third untouched.
    let f = mem_file(b"hello", OpenFlags::O_RDONLY);
    let (mut a, mut b, mut c) = ([0u8; 3], [0u8; 4], [0u8; 4]);
    let total = {
        let mut iov: [&mut [u8]; 3] = [&mut a, &mut b, &mut c];
        f.read_iter(&mut iov).unwrap()
    };
    assert_eq!(total, 5);
    assert_eq!(&a, b"hel");
    assert_eq!(&b[..2], b"lo");
    assert_eq!(&c, b"\0\0\0\0", "buffer past EOF stays untouched");
    assert_eq!(f.pos(), 5);
}

#[test]
fn read_iter_skips_empty_buffers() {
    let f = mem_file(b"XY", OpenFlags::O_RDONLY);
    let (mut a, mut c) = ([0u8; 1], [0u8; 1]);
    let total = {
        let mut empty: [u8; 0] = [];
        let mut iov: [&mut [u8]; 3] = [&mut a, &mut empty, &mut c];
        f.read_iter(&mut iov).unwrap()
    };
    assert_eq!(total, 2);
    assert_eq!((&a, &c), (b"X", b"Y"));
    assert_eq!(f.pos(), 2);
}

#[test]
fn read_iter_continues_from_cursor() {
    let f = mem_file(b"0123456789", OpenFlags::O_RDONLY);
    f.set_pos(4);
    let mut a = [0u8; 3];
    let total = { let mut iov: [&mut [u8]; 1] = [&mut a]; f.read_iter(&mut iov).unwrap() };
    assert_eq!(total, 3);
    assert_eq!(&a, b"456");
    assert_eq!(f.pos(), 7);
}

#[test]
fn read_iter_wronly_is_ebadf() {
    let f = mem_file(b"abc", OpenFlags::O_WRONLY);
    let mut a = [0u8; 1];
    let mut iov: [&mut [u8]; 1] = [&mut a];
    assert_eq!(f.read_iter(&mut iov), Err(VfsError::Ebadf));
}

#[test]
fn write_iter_concatenates_and_advances_once() {
    let f = mem_file(b"", OpenFlags::O_RDWR);
    let total = { let iov: [&[u8]; 3] = [b"AB", b"CDE", b"F"]; f.write_iter(&iov).unwrap() };
    assert_eq!(total, 6);
    assert_eq!(f.pos(), 6);
    let mut out = [0u8; 6];
    assert_eq!(f.pread(&mut out, 0), Ok(6));
    assert_eq!(&out, b"ABCDEF");
}

#[test]
fn write_iter_append_forces_base_to_size_once() {
    // O_APPEND: all buffers land at end, sequentially, regardless of f_pos.
    let f = mem_file(b"head", OpenFlags::O_RDWR | OpenFlags::O_APPEND);
    f.set_pos(0); // ignored under O_APPEND
    let total = { let iov: [&[u8]; 2] = [b"-X", b"-Y"]; f.write_iter(&iov).unwrap() };
    assert_eq!(total, 4);
    let mut out = [0u8; 8];
    assert_eq!(f.pread(&mut out, 0), Ok(8));
    assert_eq!(&out, b"head-X-Y");
}

#[test]
fn write_iter_skips_empty_buffers() {
    let f = mem_file(b"", OpenFlags::O_RDWR);
    let total = { let iov: [&[u8]; 3] = [b"a", b"", b"b"]; f.write_iter(&iov).unwrap() };
    assert_eq!(total, 2);
    let mut out = [0u8; 2];
    assert_eq!(f.pread(&mut out, 0), Ok(2));
    assert_eq!(&out, b"ab");
}

#[test]
fn write_iter_rdonly_is_ebadf() {
    let f = mem_file(b"abc", OpenFlags::O_RDONLY);
    let iov: [&[u8]; 1] = [b"x"];
    assert_eq!(f.write_iter(&iov), Err(VfsError::Ebadf));
}
