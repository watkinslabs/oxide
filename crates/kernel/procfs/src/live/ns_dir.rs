use alloc::sync::Arc;

use vfs::{DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

use super::pid_ino;

/// Every `/proc/<pid>/ns/` link Linux publishes (`proc_ns_dir_readdir` over
/// `ns_entries`); `NsKind::from_leaf` is the matching resolver.
const NS_ENTRIES: &[&str] = &["mnt", "cgroup", "uts", "ipc", "user", "pid", "net",
    "pid_for_children", "time", "time_for_children"];

pub struct ProcPidNsDirInode {
    pub tid: u32,
}

struct ProcPidNsDirOps;

impl InodeOps for ProcPidNsDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcPidNsDirInode>().ok_or(VfsError::Einval)?;
        let kind = match nscg::proc_ns::NsKind::from_leaf(name) {
            Some(k) => k,
            None => return Err(VfsError::Enoent),
        };
        let task = match sched::live::registry::lookup(d.tid) {
            Some(t) => t,
            None => return Err(VfsError::Enoent),
        };
        nscg::proc_ns::ns_inode_for(&task, kind)
    }
}

impl FileOps for ProcPidNsDirOps {
    /// A namespace link the task no longer holds (it exited between two
    /// `getdents` pages) is dropped, not emitted with `d_ino == 0`. # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let names = crate::readdir::typed(NS_ENTRIES, FileType::Symlink);
        crate::readdir::emit_resolved(names, |n| inode.lookup(n).ok().map(|i| i.ino()), ctx)
    }
}

pub fn make_proc_pid_ns_dir(tid: u32) -> InodeRef {
    InodeBuilder::new(
        pid_ino(0x08, tid),
        mk_mode(FileType::Directory, 0o555),
        Arc::new(ProcPidNsDirOps),
        Arc::new(ProcPidNsDirOps),
    )
    .private(Arc::new(ProcPidNsDirInode { tid }))
    .build()
}
