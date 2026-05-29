// `/proc/<pid>/cgroup` + `/proc/self/cgroup` inode (`26§3.7`). Split
// out of mod.rs to honor the 1000-line cap (`08§7`).

#![cfg(target_os = "oxide-kernel")]

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// `/proc/<pid>/cgroup` (and `/proc/self/cgroup`) — the unified v2
/// hierarchy path the task belongs to. `tid == None` resolves the
/// calling task at read time (for `/proc/self/cgroup`).
pub struct ProcCgroupInode { pub tid: Option<u32> }

impl Inode for ProcCgroupInode {
    fn ino(&self) -> Ino { 0x3000_0C00 | self.tid.unwrap_or(0) as Ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let pid = self.tid
            .or_else(|| sched::live::current().map(|c| c.tid))
            .unwrap_or(0) as u64;
        let data = cgroup::proc_cgroup(pid);
        let bytes = data.as_bytes();
        if off as usize >= bytes.len() { return Ok(0); }
        let n = core::cmp::min(buf.len(), bytes.len() - off as usize);
        buf[..n].copy_from_slice(&bytes[off as usize..off as usize + n]);
        Ok(n)
    }
}
