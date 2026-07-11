//! `lseek(2)` syscall shape over the real fd table + `File::seek`.
//! Linux `ksys_lseek` resolves the fd first, rejects invalid `whence` only for
//! a live fd, then calls `vfs_llseek` where `FMODE_LSEEK` yields `ESPIPE`.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, SeekFrom, VfsError,
          default_inode_ops, mk_mode};

struct OkOps;
impl FileOps for OkOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

fn file(ft: FileType, size: u64) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x15ee, mk_mode(ft, 0o644), default_inode_ops(), Arc::new(OkOps))
        .size(size).build();
    let d = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, d, OpenFlags::O_RDWR)
}

fn model_lseek(fdt: &FdTable, fd: i32, off: i64, whence: i32) -> KResult<u64> {
    let f = fdt.get(fd)?;
    let from = match whence {
        0 => SeekFrom::Start,
        1 => SeekFrom::Current,
        2 => SeekFrom::End,
        3 => SeekFrom::Data,
        4 => SeekFrom::Hole,
        _ => return Err(VfsError::Einval),
    };
    f.seek(from, off)
}

#[test]
fn bad_fd_beats_bad_whence() {
    let fdt = FdTable::new();
    assert_eq!(model_lseek(&fdt, 99, 0, 99), Err(VfsError::Ebadf));
}

#[test]
fn bad_whence_beats_seekability_after_fd_lookup() {
    let fdt = FdTable::new();
    let fd = fdt.alloc(file(FileType::Fifo, 0)).expect("fifo fd");
    assert_eq!(model_lseek(&fdt, fd, 0, 99), Err(VfsError::Einval));
    assert_eq!(model_lseek(&fdt, fd, 0, 0), Err(VfsError::Espipe));
}

#[test]
fn regular_fd_covers_linux_generic_llseek_cases() {
    let fdt = FdTable::new();
    let f = file(FileType::Regular, 8);
    let fd = fdt.alloc(f.clone()).expect("regular fd");
    assert_eq!(model_lseek(&fdt, fd, 2, 0), Ok(2));
    assert_eq!(model_lseek(&fdt, fd, 3, 1), Ok(5));
    assert_eq!(model_lseek(&fdt, fd, -1, 2), Ok(7));
    assert_eq!(model_lseek(&fdt, fd, -9, 2), Err(VfsError::Einval));
    assert_eq!(f.pos(), 7, "rejected seek leaves f_pos unchanged");
    assert_eq!(model_lseek(&fdt, fd, 0, 3), Ok(0));
    assert_eq!(model_lseek(&fdt, fd, 0, 4), Ok(8));
    assert_eq!(model_lseek(&fdt, fd, 8, 3), Err(VfsError::Enxio));
}
