//! file-D3 (remaining): the seekability of an open file description is now a
//! CANONICAL `f_mode` capability — FMODE_LSEEK / FMODE_PREAD / FMODE_PWRITE
//! (Linux `do_dentry_open`) — computed ONCE at construction, not re-derived
//! from the inode's file type on every `seek`/`pread`/`pwrite`. A seekable
//! backing (regular/dir/char/block) carries all three; an inherently streaming
//! pipe/socket/fifo and an O_PATH fd (`empty_fops`) carry none, so `lseek`/
//! `pread`/`pwrite` on them are ESPIPE.
//!
//! Pre-change `seek`/`pread`/`pwrite` each re-matched `inode.file_type()` and
//! `Fmode::PATH` inline; the bits did not exist on `f_mode`. This test asserts
//! the bits are present/absent per file type AND that the gates honor them.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, File, FileOps, FileType, Fmode, InodeBuilder, InodeRef, KResult, OpenFlags, SeekFrom, VfsError,
          default_inode_ops, mk_mode};

/// `O_PATH` (asm-generic) — not declared in `OpenFlags`; set as a raw bit and
/// preserved via `from_bits_retain`, exactly how the syscall layer hands it in.
const O_PATH: u32 = 0o10000000;

/// `i_fop` that always satisfies read/write, so the only thing that can produce
/// ESPIPE is the seekability gate under test.
struct OkOps;
impl FileOps for OkOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

fn file(ft: FileType, flags: u32) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x7373, mk_mode(ft, 0o644), default_inode_ops(), Arc::new(OkOps))
        .size(64).build();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::from_bits_retain(flags))
}

const SEEK_CAPS: Fmode = Fmode::LSEEK.union(Fmode::PREAD).union(Fmode::PWRITE);

#[test]
fn regular_file_carries_all_seek_caps() {
    let f = file(FileType::Regular, OpenFlags::O_RDWR.bits());
    assert!(f.f_mode().contains(SEEK_CAPS), "regular file is LSEEK|PREAD|PWRITE");
    // The gates pass: seek/pread/pwrite reach the backend, no ESPIPE.
    assert_eq!(f.seek(SeekFrom::Start, 8), Ok(8));
    assert!(f.pread(&mut [0u8; 4], 0).is_ok());
    assert!(f.pwrite(b"abcd", 0).is_ok());
}

#[test]
fn char_and_block_devices_are_seekable() {
    for ft in [FileType::CharDev, FileType::BlockDev] {
        let f = file(ft, OpenFlags::O_RDWR.bits());
        assert!(f.f_mode().contains(SEEK_CAPS), "char/block device is seekable");
        assert!(f.seek(SeekFrom::Start, 0).is_ok());
    }
}

#[test]
fn fifo_and_socket_lack_seek_caps() {
    for ft in [FileType::Fifo, FileType::Socket] {
        let f = file(ft, OpenFlags::O_RDWR.bits());
        assert!(!f.f_mode().intersects(SEEK_CAPS), "pipe/socket has no seek caps");
        assert_eq!(f.seek(SeekFrom::Start, 0), Err(VfsError::Espipe), "non-seekable lseek = ESPIPE");
        assert_eq!(f.pread(&mut [0u8; 4], 0), Err(VfsError::Espipe), "non-seekable pread = ESPIPE");
        assert_eq!(f.pwrite(b"x", 0), Err(VfsError::Espipe), "non-seekable pwrite = ESPIPE");
    }
}

#[test]
fn o_path_fd_has_no_seek_caps_even_on_regular_file() {
    // An O_PATH fd over a regular file is FMODE_PATH only — no read/write and
    // no seek caps, so positional I/O and lseek are ESPIPE despite a seekable
    // backing inode.
    let f = file(FileType::Regular, O_PATH);
    assert_eq!(f.f_mode(), Fmode::PATH, "O_PATH fd is FMODE_PATH only");
    assert!(!f.f_mode().intersects(SEEK_CAPS), "O_PATH has no seek caps");
    assert_eq!(f.seek(SeekFrom::Start, 0), Err(VfsError::Espipe));
    assert_eq!(f.pread(&mut [0u8; 4], 0), Err(VfsError::Espipe));
    assert_eq!(f.pwrite(b"x", 0), Err(VfsError::Espipe));
}
