// procfs symlink inodes: /proc/self/{exe,cwd,root} + per-fd
// symlinks. Each delegates to `sched::proclink::resolve_proc_link`
// at readlink time so the target reflects live task state.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Per-fd symlink under `/proc/self/fd/<n>` (and per-pid analogue).
/// `target` is the path bytes returned by readlink(2); `ino` is a
/// stable distinguisher so getdents reflects the fd.
pub struct ProcFdLinkInode {
    pub target: Vec<u8>,
    pub ino:    Ino,
}

impl Inode for ProcFdLinkInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> { Ok(self.target.clone()) }
}

/// `/proc/self/exe` symlink — resolves to the current task's
/// `mm.exe_path` (the path the kernel saw at execve).
pub struct ProcSelfExeInode;

impl Inode for ProcSelfExeInode {
    fn ino(&self) -> Ino { 0x3000_1700 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> {
        Ok(sched::proclink::resolve_proc_link("/proc/self/exe")
            .unwrap_or_else(|| b"/init".to_vec()))
    }
}

/// `/proc/self/cwd` symlink.
pub struct ProcSelfCwdInode;

impl Inode for ProcSelfCwdInode {
    fn ino(&self) -> Ino { 0x3000_1701 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> {
        Ok(sched::proclink::resolve_proc_link("/proc/self/cwd")
            .unwrap_or_else(|| b"/".to_vec()))
    }
}

/// `/proc/self/root` symlink.
pub struct ProcSelfRootInode;

impl Inode for ProcSelfRootInode {
    fn ino(&self) -> Ino { 0x3000_1702 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> {
        Ok(sched::proclink::resolve_proc_link("/proc/self/root")
            .unwrap_or_else(|| b"/".to_vec()))
    }
}

/// Build a per-fd symlink inode targeting the open File's path.
/// Used by `ProcSelfFdInode::lookup`.
/// # C: O(target_len)
pub fn fd_link_for_path(path: &[u8], fd: i32) -> InodeRef {
    Arc::new(ProcFdLinkInode {
        target: path.to_vec(),
        ino:    0x3000_1600 | (fd as Ino),
    })
}
