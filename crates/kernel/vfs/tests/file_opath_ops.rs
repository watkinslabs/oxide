//! file-D3 (O_PATH op restrictions): an `O_PATH` descriptor is an fd-reference
//! only — it carries FMODE_PATH and NONE of READ/WRITE/LSEEK/PREAD/PWRITE, so
//! every data/seek op on it is refused (Linux `empty_fops`: read/write →
//! `EBADF`, lseek/pread/pwrite → `ESPIPE`). The scalar read/write rejection is
//! covered by `file_fmode.rs`; this pins the FULL op surface — including the
//! vectored `read_iter`/`write_iter` and the positional/seek ESPIPE paths —
//! over an inode whose own I/O always succeeds, so the only possible refusal is
//! the `f_mode` gate. Validates the F649 worktree already enforces the whole
//! set (ledger was stale-pessimistic that O_PATH is "production-inert").

use std::sync::Arc;

use vfs::file::SeekFrom;
use vfs::inode::Inode;
use vfs::{Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
          default_inode_ops, mk_mode};

/// `O_PATH` (asm-generic) — undeclared in `OpenFlags`, set as a raw bit and
/// preserved via `from_bits_retain`, exactly how the syscall layer hands it in.
const O_PATH: u32 = 0o10000000;

/// Regular-file `i_fop` whose every I/O op succeeds — so any error returned by a
/// `File` op can ONLY come from the O_PATH `f_mode` gate.
struct AlwaysOkOps;
impl FileOps for AlwaysOkOps {
    fn read(&self, _inode: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> { Ok(b.len()) }
    fn write(&self, _inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}

fn opath_file() -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x9a7, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(AlwaysOkOps))
        .size(4096).build();
    let d = Dentry::new(None, "p".into(), Arc::clone(&ino));
    File::new(ino, d, OpenFlags::from_bits_retain(O_PATH))
}

#[test]
fn opath_has_only_fmode_path() {
    let f = opath_file();
    let m = f.f_mode();
    assert!(m.contains(vfs::Fmode::PATH), "O_PATH fd carries FMODE_PATH");
    assert!(!m.contains(vfs::Fmode::READ) && !m.contains(vfs::Fmode::WRITE),
        "O_PATH fd lacks READ/WRITE");
    assert!(!m.contains(vfs::Fmode::LSEEK), "O_PATH fd lacks FMODE_LSEEK");
}

#[test]
fn opath_read_write_ebadf() {
    let f = opath_file();
    assert_eq!(f.read(&mut [0u8; 8]), Err(VfsError::Ebadf), "O_PATH read → EBADF");
    assert_eq!(f.write(b"data"), Err(VfsError::Ebadf), "O_PATH write → EBADF");
}

#[test]
fn opath_vectored_ebadf() {
    let f = opath_file();
    let mut a = [0u8; 4];
    let mut b = [0u8; 4];
    let mut iov: [&mut [u8]; 2] = [&mut a, &mut b];
    assert_eq!(f.read_iter(&mut iov), Err(VfsError::Ebadf), "O_PATH readv → EBADF");
    let src: [&[u8]; 1] = [b"x"];
    assert_eq!(f.write_iter(&src), Err(VfsError::Ebadf), "O_PATH writev → EBADF");
}

#[test]
fn opath_seek_pread_pwrite_espipe() {
    let f = opath_file();
    assert_eq!(f.seek(SeekFrom::Start, 0), Err(VfsError::Espipe), "O_PATH lseek → ESPIPE");
    assert_eq!(f.pread(&mut [0u8; 8], 0), Err(VfsError::Espipe), "O_PATH pread → ESPIPE");
    assert_eq!(f.pwrite(b"x", 0), Err(VfsError::Espipe), "O_PATH pwrite → ESPIPE");
}
