// `/proc/<pid>/cgroup` + `/proc/self/cgroup` inode (`26§3.7`). Split
// out of mod.rs to honor the 1000-line cap (`08§7`).

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError};

use crate::dyn_file::read_at;

/// `i_private` for `/proc/<pid>/cgroup` (and `/proc/self/cgroup`) — the
/// unified v2 hierarchy path the task belongs to. `tid == None` resolves the
/// calling task at read time (for `/proc/self/cgroup`).
pub struct ProcCgroupInode { pub tid: Option<u32> }

/// `i_fop` for `/proc/<pid>/cgroup` — renders the task's cgroup path at read.
struct CgroupFileOps;
impl FileOps for CgroupFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<ProcCgroupInode>().ok_or(VfsError::Einval)?;
        let tid = d.tid
            .or_else(|| sched::live::current().map(|c| c.tid))
            .unwrap_or(0);
        // cgroup membership is per thread-GROUP (Linux: css_set is shared by
        // every thread of a process). `tid` may be a non-leader thread — this
        // inode backs `/proc/<pid>/task/<tid>/cgroup` as well as a
        // `/proc/self/cgroup` read issued from a worker thread. Resolve to the
        // group leader's tid (== tgid), which is the ONLY key the cgroup tree
        // stores process membership under, so the read reflects the process's
        // cgroup rather than the root cgroup. Best-effort: fall back to the raw
        // tid if the task has exited (yields `0::/`, matching a dead task).
        let proc_tid = sched::live::registry::lookup(tid)
            .map(|t| t.tgid.load(core::sync::atomic::Ordering::Acquire))
            .unwrap_or(tid);
        let data = cgroup::proc_cgroup(proc_tid as u64);
        Ok(read_at(data.as_bytes(), off, buf))
    }
}

/// `/proc/<pid>/cgroup` (and `/proc/self/cgroup`) inode. # C: O(1)
pub fn make_proc_cgroup(tid: Option<u32>) -> InodeRef {
    let ino: Ino = crate::live::pid_ino(0x0C, tid.unwrap_or(0));
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o444), default_inode_ops(), Arc::new(CgroupFileOps))
        .private(Arc::new(ProcCgroupInode { tid }))
        .build()
}
