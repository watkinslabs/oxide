// Descriptor and buffer resolution for one operation.
//
// Three indirections an SQE can ask for, all resolved here so no opcode
// handler re-implements one:
//   * `IOSQE_FIXED_FILE` — the SQE's `fd` is a registered-file index. The
//     registered description is installed at a scratch descriptor for the life
//     of the operation, because the per-op handlers resolve descriptors
//     through the task's table.
//   * a direct descriptor request (`file_index`) — the descriptor an
//     operation creates goes into a registered-file slot instead of the task's
//     table, and never becomes visible to userspace.
//   * `IOSQE_BUFFER_SELECT` — the target buffer comes from a provided-buffer
//     group rather than the SQE.

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::File;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::rsrc::{alloc_window, ProvidedBuf, RegFile};
use crate::io_uring_abi::ops::IOSQE_FIXED_FILE;
use crate::io_uring_sqe::Sqe;

/// `IORING_FILE_INDEX_ALLOC` — pick any free slot in the allocation window.
pub const IORING_FILE_INDEX_ALLOC: u32 = u32::MAX;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Resolve a registered-file index. # C: O(1)
pub fn fixed_file(inode: &IoUringInode, idx: u32) -> Result<Arc<File>, i64> {
    let g = inode.reg.lock();
    match g.files.as_ref().and_then(|f| f.get(idx as usize)).and_then(|s| s.file.clone()) {
        Some(f) => Ok(f),
        None    => Err(err(Errno::Ebadf)),
    }
}

/// A descriptor installed for the life of one operation.
pub struct ScratchFd(pub i32);

impl Drop for ScratchFd {
    /// # C: O(1)
    fn drop(&mut self) {
        if let Some(cur) = sched::live::current() {
            // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot for the scratch descriptor.
            if let Some(t) = unsafe { cur.fd_table_ref() } { let _ = t.clone().close(self.0); }
        }
    }
}

/// Install `file` at the lowest free descriptor of the current task.
/// # C: O(N_fds)
pub fn install_scratch(file: Arc<File>) -> Result<ScratchFd, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot for the scratch install.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
    match fdt.clone().alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => Ok(ScratchFd(fd)),
        Err(e) => Err(-(e as i64)),
    }
}

/// The descriptor an operation should act on, plus the scratch registration
/// that must outlive it. # C: O(N_fds)
pub fn effective_fd(inode: &IoUringInode, sqe: &Sqe) -> Result<(i32, Option<ScratchFd>), i64> {
    if sqe.flags & IOSQE_FIXED_FILE == 0 { return Ok((sqe.fd, None)); }
    let f = fixed_file(inode, sqe.fd as u32)?;
    let s = install_scratch(f)?;
    Ok((s.0, Some(s)))
}

/// Take a descriptor out of the task's table and put it in a registered-file
/// slot. `want` is the SQE's 1-based `file_index`, or `IORING_FILE_INDEX_ALLOC`
/// to pick a free slot inside the allocation window. Returns the slot index,
/// which is what an allocating request reports. # C: O(N_slots)
pub fn into_direct_slot(inode: &IoUringInode, fd: i32, want: u32) -> Result<u32, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot for the direct-descriptor move.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
    let fdt = fdt.clone();
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return Err(err(Errno::Ebadf)) };

    let mut g = inode.reg.lock();
    let range = g.alloc_range;
    let Some(table) = g.files.as_mut() else { let _ = fdt.close(fd); return Err(err(Errno::Enxio)) };
    let slot = if want == IORING_FILE_INDEX_ALLOC {
        let (lo, hi) = alloc_window(range, table.len() as u32);
        match (lo..hi).find(|&i| table[i as usize].file.is_none()) {
            Some(i) => i,
            None => { drop(g); let _ = fdt.close(fd); return Err(err(Errno::Enfile)); }
        }
    } else {
        let i = want - 1;
        if i as usize >= table.len() { drop(g); let _ = fdt.close(fd); return Err(err(Errno::Einval)); }
        if table[i as usize].file.is_some() { drop(g); let _ = fdt.close(fd); return Err(err(Errno::Ebadf)); }
        i
    };
    table[slot as usize] = RegFile { file: Some(file), tag: 0 };
    drop(g);
    // The descriptor was only ever a carrier: userspace never sees it.
    let _ = fdt.close(fd);
    Ok(slot)
}

/// Whether this SQE asks for a direct descriptor. # C: O(1)
pub fn wants_direct(sqe: &Sqe) -> bool { sqe.file_index() != 0 }

/// Turn a descriptor-creating result into a direct descriptor when the SQE
/// asked for one. # C: O(N_slots)
pub fn place_result(inode: &IoUringInode, sqe: &Sqe, rv: i64) -> i64 {
    if rv < 0 || !wants_direct(sqe) { return rv; }
    match into_direct_slot(inode, rv as i32, sqe.file_index()) {
        Ok(slot) => if sqe.file_index() == IORING_FILE_INDEX_ALLOC { slot as i64 } else { 0 },
        Err(e) => e,
    }
}

/// A buffer taken from a provided-buffer group, put back if the operation
/// never used it.
pub struct SelectedBuf<'a> {
    pub buf: ProvidedBuf,
    inode: &'a IoUringInode,
    gid: u16,
    consumed: bool,
}

impl SelectedBuf<'_> {
    /// The operation used the buffer: keep it out of the group. # C: O(1)
    pub fn consume(&mut self) { self.consumed = true; }
}

impl Drop for SelectedBuf<'_> {
    /// # C: O(N_groups)
    fn drop(&mut self) {
        if !self.consumed { self.inode.reg.lock().unselect_buf(self.gid, self.buf); }
    }
}

/// Take the next buffer from the group the SQE names. # C: O(N_groups)
pub fn select_buf<'a>(inode: &'a IoUringInode, gid: u16) -> Result<SelectedBuf<'a>, i64> {
    let buf = inode.reg.lock().select_buf(gid).map_err(err)?;
    Ok(SelectedBuf { buf, inode, gid, consumed: false })
}
