//! `File::read`/`write` gate on `f_mode` (FMODE_*), not raw `OpenFlags`
//! (file-D3). The bug: an `O_PATH` fd (FMODE_PATH, no read/write) was NOT
//! rejected on `read()` and would be read; Linux returns EBADF for read/write
//! on an O_PATH fd. Here we drive the real `File` over a read+write-backed
//! inode with each access mode and assert the gate.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, File, FileType, InodeRef, KResult, OpenFlags, VfsError};

/// `O_PATH` (asm-generic) — not declared in `OpenFlags`, so the test sets it as
/// a raw bit and constructs the `File` with `from_bits_retain` to preserve it,
/// exactly how the syscall layer must hand O_PATH through to `File`.
const O_PATH: u32 = 0o10000000;

/// Regular-file inode that always satisfies read + write, so the only thing
/// that can produce EBADF is the `f_mode` gate under test.
struct RwFile;
impl Inode for RwFile {
    fn ino(&self) -> vfs::Ino { 0x4242 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

/// Build a `File` over `RwFile` with the given raw open flags (retaining
/// unknown bits like O_PATH).
fn file(flags: u32) -> Arc<File> {
    let ino: InodeRef = Arc::new(RwFile);
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::from_bits_retain(flags))
}

#[test]
fn rdonly_reads_not_writes() {
    let f = file(OpenFlags::O_RDONLY.bits());
    assert!(f.read(&mut [0u8; 4]).is_ok(), "O_RDONLY read should not be EBADF");
    assert_eq!(f.write(b"x"), Err(VfsError::Ebadf), "O_RDONLY write must be EBADF");
}

#[test]
fn wronly_writes_not_reads() {
    let f = file(OpenFlags::O_WRONLY.bits());
    assert!(f.write(b"x").is_ok(), "O_WRONLY write should not be EBADF");
    assert_eq!(f.read(&mut [0u8; 4]), Err(VfsError::Ebadf), "O_WRONLY read must be EBADF");
}

#[test]
fn rdwr_reads_and_writes() {
    let f = file(OpenFlags::O_RDWR.bits());
    assert_ne!(f.read(&mut [0u8; 4]), Err(VfsError::Ebadf), "O_RDWR read must not be EBADF");
    assert_ne!(f.write(b"x"), Err(VfsError::Ebadf), "O_RDWR write must not be EBADF");
}

/// The crux of file-D3: an O_PATH fd has FMODE_PATH only — BOTH read and write
/// are EBADF. Pre-fix, `read()` did NOT reject (access bits = O_RDONLY ⇒
/// FMODE_READ) and this assertion FAILS; post-fix it passes.
#[test]
fn o_path_rejects_read_and_write() {
    let f = file(O_PATH); // access mode bits = 0 (would look like O_RDONLY)
    assert_eq!(f.f_mode(), vfs::Fmode::PATH, "O_PATH fd is FMODE_PATH only");
    assert_eq!(f.read(&mut [0u8; 4]), Err(VfsError::Ebadf), "O_PATH read must be EBADF");
    assert_eq!(f.write(b"x"), Err(VfsError::Ebadf), "O_PATH write must be EBADF");
}
