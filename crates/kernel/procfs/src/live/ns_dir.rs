use alloc::sync::Arc;

use vfs::{DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

use super::pid_ino;

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
        Ok(nscg::proc_ns::ns_inode_for(&task, kind))
    }
}

impl FileOps for ProcPidNsDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const NAMES: &[&str] = &["mnt", "cgroup", "uts", "ipc", "user", "pid", "net", "pid_for_children"];
        let mut idx = ctx.pos as usize;
        while idx < NAMES.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(NAMES[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(NAMES[idx], ino, FileType::Symlink, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
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
