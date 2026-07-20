use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};

use super::pid_ino;
use crate::dyn_file::read_at;

const PROC_OOM_SCORE_MODE: u16 = 0o444;
const PROC_OOM_SCORE_ADJ_MODE: u16 = 0o644;
const OOM_SCORE_TAG: u64 = 0x46;
const OOM_SCORE_ADJ_TAG: u64 = 0x47;

struct OomTaskFile { tid: u32, adjustment: bool }

fn task(tid: u32) -> KResult<Arc<sched::Task>> {
    sched::live::registry::lookup(tid).ok_or(VfsError::Enoent)
}

fn decimal_line(value: i32) -> Vec<u8> {
    let mut out = alloc::format!("{value}\n").into_bytes();
    if out.is_empty() { out.push(b'0'); }
    out
}

fn parse_adjustment(src: &[u8]) -> Result<i32, VfsError> {
    let text = core::str::from_utf8(src).map_err(|_| VfsError::Einval)?.trim();
    text.parse::<i32>().map_err(|_| VfsError::Einval)
}

fn may_write_adjustment(target: &sched::Task, next: i32) -> KResult<()> {
    let current = sched::live::current().ok_or(VfsError::Eperm)?;
    let privileged = current.has_cap(sched::cap::SYS_RESOURCE);
    if current.tid != target.tid && !privileged { return Err(VfsError::Eperm); }
    if next < target.oom_score_adj() && !privileged { return Err(VfsError::Eperm); }
    Ok(())
}

struct OomTaskFileOps;
impl FileOps for OomTaskFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<OomTaskFile>().ok_or(VfsError::Einval)?;
        let task = task(data.tid)?;
        let line = if data.adjustment {
            decimal_line(task.oom_score_adj())
        } else {
            decimal_line(sched::oom::task_score(&task).unwrap_or(0) as i32)
        };
        Ok(read_at(&line, off, buf))
    }

    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let data = inode.private::<OomTaskFile>().ok_or(VfsError::Einval)?;
        if !data.adjustment { return Err(VfsError::Erofs); }
        if off != 0 { return Ok(src.len()); }
        let target = task(data.tid)?;
        let adjustment = parse_adjustment(src)?;
        may_write_adjustment(&target, adjustment)?;
        if !target.set_oom_score_adj(adjustment) { return Err(VfsError::Einval); }
        Ok(src.len())
    }
}

fn make(tid: u32, adjustment: bool) -> InodeRef {
    let tag = if adjustment { OOM_SCORE_ADJ_TAG } else { OOM_SCORE_TAG };
    let mode = if adjustment { PROC_OOM_SCORE_ADJ_MODE } else { PROC_OOM_SCORE_MODE };
    let ino = pid_ino(tag, tid);
    InodeBuilder::new(ino, mk_mode(FileType::Regular, mode), default_inode_ops(), Arc::new(OomTaskFileOps))
        .private(Arc::new(OomTaskFile { tid, adjustment }))
        .build()
}

/// Live `/proc/<pid>/oom_score` source. # C: O(mapped user pages)
pub fn make_pid_oom_score(tid: u32) -> InodeRef { make(tid, false) }

/// Live writable `/proc/<pid>/oom_score_adj` source. # C: O(1)
pub fn make_pid_oom_score_adj(tid: u32) -> InodeRef { make(tid, true) }
