//! `File::pread` / `File::pwrite` — positional I/O at an explicit offset that
//! does NOT touch `f_pos` (Linux `ksys_pread64`/`ksys_pwrite64` use a local
//! `pos`, bypassing `__fdget_pos`). Driven over a real `File` wrapping an
//! in-memory regular-file inode so only the positional dispatch + gate logic
//! is under test.
//!
//! Before this change `File` exposed only `read`/`write` (cursor-advancing);
//! there was no way to do a pread/pwrite without mutating the shared cursor —
//! these assertions did not compile.

use std::sync::{Arc, Mutex};

use vfs::inode::Inode;
use vfs::{Dentry, File, FileType, FileOps, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
          default_file_ops, default_inode_ops, mk_mode};

/// Regular-file inode backed by a growable byte vector. `read`/`write` honor
/// the explicit offset so a positional op can be observed end-to-end;
/// `inode.set_size` tracks the live length for the `O_APPEND` pwrite gate.
struct MemData(Mutex<Vec<u8>>);
struct MemOps;
impl FileOps for MemOps {
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
    let ino: InodeRef = InodeBuilder::new(0x9ead, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(MemOps))
        .size(init.len() as u64)
        .private(Arc::new(MemData(Mutex::new(init.to_vec()))))
        .build();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

fn fifo_file(flags: OpenFlags) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0xf1f0, mk_mode(FileType::Fifo, 0o644), default_inode_ops(), default_file_ops()).build();
    let dentry = Dentry::new(None, "p".into(), Arc::clone(&ino));
    File::new(ino, dentry, flags)
}

#[test]
fn pread_does_not_move_cursor() {
    let f = mem_file(b"ABCDEFGH", OpenFlags::O_RDONLY);
    f.set_pos(5);
    let mut buf = [0u8; 3];
    assert_eq!(f.pread(&mut buf, 1), Ok(3));
    assert_eq!(&buf, b"BCD");
    // The defining property: f_pos is untouched by a positional read.
    assert_eq!(f.pos(), 5, "pread must not advance f_pos");
}

#[test]
fn pwrite_does_not_move_cursor() {
    let f = mem_file(b"........", OpenFlags::O_RDWR);
    f.set_pos(2);
    assert_eq!(f.pwrite(b"XYZ", 4), Ok(3));
    assert_eq!(f.pos(), 2, "pwrite must not advance f_pos");
    let mut buf = [0u8; 8];
    assert_eq!(f.pread(&mut buf, 0), Ok(8));
    assert_eq!(&buf, b"....XYZ.");
}

#[test]
fn pread_negative_offset_is_einval() {
    let f = mem_file(b"abc", OpenFlags::O_RDONLY);
    assert_eq!(f.pread(&mut [0u8; 1], -1), Err(VfsError::Einval));
}

#[test]
fn pwrite_negative_offset_is_einval() {
    let f = mem_file(b"abc", OpenFlags::O_RDWR);
    assert_eq!(f.pwrite(b"x", -1), Err(VfsError::Einval));
}

#[test]
fn pread_wronly_is_ebadf() {
    let f = mem_file(b"abc", OpenFlags::O_WRONLY);
    assert_eq!(f.pread(&mut [0u8; 1], 0), Err(VfsError::Ebadf));
}

#[test]
fn pwrite_rdonly_is_ebadf() {
    let f = mem_file(b"abc", OpenFlags::O_RDONLY);
    assert_eq!(f.pwrite(b"x", 0), Err(VfsError::Ebadf));
}

#[test]
fn pread_on_fifo_is_espipe() {
    let f = fifo_file(OpenFlags::O_RDONLY);
    assert_eq!(f.pread(&mut [0u8; 1], 0), Err(VfsError::Espipe));
}

#[test]
fn pwrite_on_fifo_is_espipe() {
    let f = fifo_file(OpenFlags::O_WRONLY);
    assert_eq!(f.pwrite(b"x", 0), Err(VfsError::Espipe));
}

#[test]
fn pread_on_opath_is_espipe() {
    // O_PATH fd lacks FMODE_PREAD (empty_fops) -> ESPIPE before the read gate.
    let f = mem_file(b"abc", OpenFlags::from_bits_retain(0o10000000));
    assert_eq!(f.pread(&mut [0u8; 1], 0), Err(VfsError::Espipe));
}

#[test]
fn pwrite_append_forces_offset_to_size() {
    // Linux pwrite + O_APPEND quirk (pwrite(2) BUGS): IOCB_APPEND forces the
    // write to i_size, ignoring the supplied offset.
    let f = mem_file(b"hello", OpenFlags::O_RDWR | OpenFlags::O_APPEND);
    // Ask to write at offset 0; append must instead land at end (size 5).
    assert_eq!(f.pwrite(b"!!", 0), Ok(2));
    let mut buf = [0u8; 7];
    assert_eq!(f.pread(&mut buf, 0), Ok(7));
    assert_eq!(&buf, b"hello!!", "O_APPEND pwrite appends regardless of offset");
}
