use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::Task;

const GETDENTS_STAGE_NONE: u8 = 0;
pub const GETDENTS_STAGE_VALIDATED: u8 = 1;
pub const GETDENTS_STAGE_READDIR_ENTER: u8 = 2;
pub const GETDENTS_STAGE_READDIR_EXIT: u8 = 3;
pub const GETDENTS_STAGE_COPYOUT_DONE: u8 = 4;
pub const GETDENTS_STAGE_COPYOUT_OVERFLOW: u8 = 5;
const GETDENTS_BACKEND_UNKNOWN: u8 = vfs::DirDebugBackend::Unknown as u8;

/// Task-owned active getdents metadata, read only by watchdog/task dumps. # C: O(1)
pub(crate) struct GetdentsState {
    stage: AtomicU8,
    fd: AtomicI32,
    mount: AtomicU64,
    inode: AtomicU64,
    fpos: AtomicU64,
    count: AtomicU64,
    result: AtomicI64,
    backend: AtomicU8,
    block: AtomicU32,
    entries: AtomicU64,
}

impl GetdentsState {
    pub(crate) const fn new() -> Self {
        Self { stage: AtomicU8::new(GETDENTS_STAGE_NONE), fd: AtomicI32::new(0),
               mount: AtomicU64::new(0), inode: AtomicU64::new(0), fpos: AtomicU64::new(0),
               count: AtomicU64::new(0), result: AtomicI64::new(0),
               backend: AtomicU8::new(GETDENTS_BACKEND_UNKNOWN), block: AtomicU32::new(0),
               entries: AtomicU64::new(0) }
    }
}

/// Mark the current task's admitted getdents operation active. # C: O(1)
pub fn getdents_begin(task: &Task, fd: i32, mount: u64, inode: u64, fpos: u64, count: usize) {
    let s = &task.getdents;
    s.fd.store(fd, Ordering::Relaxed);
    s.mount.store(mount, Ordering::Relaxed);
    s.inode.store(inode, Ordering::Relaxed);
    s.fpos.store(fpos, Ordering::Relaxed);
    s.count.store(count as u64, Ordering::Relaxed);
    s.result.store(0, Ordering::Relaxed);
    s.backend.store(GETDENTS_BACKEND_UNKNOWN, Ordering::Relaxed);
    s.block.store(0, Ordering::Relaxed);
    s.entries.store(0, Ordering::Relaxed);
    s.stage.store(GETDENTS_STAGE_VALIDATED, Ordering::Release);
}

/// Advance the active operation's semantic stage. # C: O(1)
pub fn getdents_stage(task: &Task, stage: u8, fpos: u64, result: i64) {
    let s = &task.getdents;
    s.fpos.store(fpos, Ordering::Relaxed);
    s.result.store(result, Ordering::Relaxed);
    s.stage.store(stage, Ordering::Release);
}

/// Retain the VFS-owned backend/block/progress checkpoint in the current task. # C: O(1)
pub fn getdents_progress(task: &Task, backend: vfs::DirDebugBackend, block: u32, entries: u64, pos: u64) {
    let s = &task.getdents;
    s.backend.store(backend as u8, Ordering::Relaxed);
    s.block.store(block, Ordering::Relaxed);
    s.entries.store(entries, Ordering::Relaxed);
    s.fpos.store(pos, Ordering::Relaxed);
}

/// Clear the current task's operation only after its terminal stage was stored. # C: O(1)
pub fn getdents_clear(task: &Task) { task.getdents.stage.store(GETDENTS_STAGE_NONE, Ordering::Release); }

/// Render active getdents state only from watchdog/task-dump context. # C: O(1)
pub(crate) fn emit_getdents(task: &Task) {
    let s = &task.getdents;
    let stage = s.stage.load(Ordering::Acquire);
    if stage == GETDENTS_STAGE_NONE { return; }
    klog::write_raw(b" getdents=");
    klog::write_raw(stage_name(stage));
    klog::write_raw(b" fd="); klog::write_dec_u64(s.fd.load(Ordering::Relaxed) as u32 as u64);
    klog::write_raw(b" mnt="); klog::write_dec_u64(s.mount.load(Ordering::Relaxed));
    klog::write_raw(b" ino="); klog::write_dec_u64(s.inode.load(Ordering::Relaxed));
    klog::write_raw(b" fpos="); klog::write_dec_u64(s.fpos.load(Ordering::Relaxed));
    klog::write_raw(b" count="); klog::write_dec_u64(s.count.load(Ordering::Relaxed));
    klog::write_raw(b" result="); klog::write_hex_u64(s.result.load(Ordering::Relaxed) as u64);
    klog::write_raw(b" backend=");
    klog::write_raw(backend_name(s.backend.load(Ordering::Relaxed)));
    klog::write_raw(b" block="); klog::write_dec_u64(s.block.load(Ordering::Relaxed) as u64);
    klog::write_raw(b" entries="); klog::write_dec_u64(s.entries.load(Ordering::Relaxed));
}

fn stage_name(stage: u8) -> &'static [u8] {
    match stage {
        GETDENTS_STAGE_VALIDATED => b"validated", GETDENTS_STAGE_READDIR_ENTER => b"readdir-enter",
        GETDENTS_STAGE_READDIR_EXIT => b"readdir-exit", GETDENTS_STAGE_COPYOUT_DONE => b"copyout-done",
        GETDENTS_STAGE_COPYOUT_OVERFLOW => b"copyout-overflow", _ => b"unknown",
    }
}

fn backend_name(backend: u8) -> &'static [u8] {
    match backend { x if x == vfs::DirDebugBackend::Ext4 as u8 => b"ext4", _ => b"unknown" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_stage_and_backend_names_are_stable() {
        assert_eq!(stage_name(GETDENTS_STAGE_READDIR_ENTER), b"readdir-enter");
        assert_eq!(stage_name(GETDENTS_STAGE_COPYOUT_DONE), b"copyout-done");
        assert_eq!(backend_name(vfs::DirDebugBackend::Ext4 as u8), b"ext4");
    }
}
