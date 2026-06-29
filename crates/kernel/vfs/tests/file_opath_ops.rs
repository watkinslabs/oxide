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
use vfs::idmap::Idmap;
use vfs::inode::Inode;
use vfs::{Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
          default_inode_ops, mk_mode};

/// `O_PATH` (asm-generic, both arches — Linux `fcntl.h` `010000000`). Now a
/// DECLARED `OpenFlags` bit (single source of truth, vfs `types.rs`), so the
/// open path's `from_bits_truncate(flags)` preserves it instead of stripping
/// it (pinned by `opath_bit_not_truncated`).
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

/// The syscall path converts the raw open word via `OpenFlags::from_bits_truncate`
/// (002_open / 257_openat). Pin that O_PATH is now a DECLARED bit, so truncation
/// PRESERVES it (the ledger's "257_openat strips the bit" is closed) and an open
/// built from the truncated flags still yields FMODE_PATH. Without the declaration
/// `from_bits_truncate` would silently drop O_PATH and the fd would behave as a
/// normal read fd.
#[test]
fn opath_bit_not_truncated() {
    // The exact transform the open handlers apply to the user `flags` word.
    let truncated = OpenFlags::from_bits_truncate(O_PATH);
    assert!(truncated.contains(OpenFlags::O_PATH), "from_bits_truncate keeps O_PATH (not stripped)");
    assert_eq!(OpenFlags::O_PATH.bits(), O_PATH, "typed O_PATH matches the asm-generic value");

    // An open built from the truncated flags (as the syscall layer does) is FMODE_PATH.
    let ino: InodeRef = InodeBuilder::new(0x9a8, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(AlwaysOkOps))
        .size(4096).build();
    let d = Dentry::new(None, "p".into(), Arc::clone(&ino));
    let f = File::new(ino, d, truncated);
    assert!(f.f_mode().contains(vfs::Fmode::PATH), "open via from_bits_truncate(O_PATH) → FMODE_PATH");
    assert!(!f.f_mode().contains(vfs::Fmode::READ), "O_PATH fd is not readable");
}

/// `fstat(2)` is one of the operations Linux PERMITS on an O_PATH fd (it reads
/// the referenced inode's attributes). Confirm the inode behind an O_PATH File
/// still answers `getattr` with the real size/mode — the FMODE_PATH gate refuses
/// data ops but never the stat path.
#[test]
fn opath_fstat_works() {
    let f = opath_file();
    let st = f.inode().getattr(&Idmap::identity(), None);
    assert_eq!(st.size, 4096, "fstat on O_PATH fd reports the real size");
    assert_eq!(st.mode & 0o7777, 0o644, "fstat on O_PATH fd reports the real mode");
}
