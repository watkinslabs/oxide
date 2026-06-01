// Writable `/proc/sys/*` tunables (R5). systemd-sysctl applies
// `/etc/sysctl.d/*.conf` by writing these; a `StaticFileInode` returns
// EROFS and the unit fails. `SysctlInode` is a mutable byte slot: writes
// persist, reads reflect the latest write (seeded with a Linux-plausible
// default). The kernel doesn't yet *act* on most tunables (swappiness,
// overcommit are advisory in v1's VM); R5's contract is that userspace
// can set+get them without error so sysctl-applying tools succeed.
//
// Genuine read-only constants (cap_last_cap, ngroups_max, ostype, …)
// stay `StaticFileInode` — Linux rejects writes to those too.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

use core::sync::atomic::Ordering;
use super::NEXT_INO;

/// A mutable sysctl value. Stored verbatim (callers write e.g. "1\n" or
/// "1"); reads return exactly the stored bytes.
pub struct SysctlInode {
    ino: Ino,
    val: Spinlock<Vec<u8>, TaskListClass>,
}

impl SysctlInode {
    /// New writable sysctl seeded with `default`.
    /// # C: O(len default)
    pub fn new(default: &[u8]) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
            val: Spinlock::new(default.to_vec()),
        })
    }
}

impl Inode for SysctlInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.val.lock().len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = self.val.lock();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, off: u64, src: &[u8]) -> KResult<usize> {
        // sysctl writes replace the value (offset 0). A normal `echo >`
        // truncates first; we treat any write as a full replace so the
        // stored value always reflects the last writer.
        if off == 0 {
            let mut v = self.val.lock();
            v.clear();
            v.extend_from_slice(src);
        }
        Ok(src.len())
    }
}
