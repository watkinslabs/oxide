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
use crate::io_uring_abi::bundle::BufEntry;
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

/// Take an owning handle on a registered buffer.
///
/// Owning on purpose: the transfer below it sleeps, and the registration
/// table's lock may not be held across that. The handle is what keeps the
/// pinned frames alive if the registration is replaced or dropped while the
/// transfer runs — a fixed-buffer transfer is exactly where a registration
/// must not be able to outlive its pin. # C: O(1)
pub fn reg_buf(inode: &IoUringInode, idx: u32)
    -> Result<Arc<crate::io_uring::pin::PinnedRange>, i64>
{
    let g = inode.reg.lock();
    let Some(bufs) = g.buffers.as_ref() else { return Err(err(Errno::Efault)) };
    let Some(slot) = bufs.get(idx as usize) else { return Err(err(Errno::Efault)) };
    Ok(Arc::clone(&slot.buf))
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

/// The head buffer of a provided-buffer group, looked at but not yet taken.
/// Nothing moves in the group until the operation says how much of the buffer
/// it used, so an operation that failed leaves the buffer where it was.
pub struct SelectedBuf<'a> {
    pub buf: ProvidedBuf,
    inode: &'a IoUringInode,
    gid: u16,
    entry: [BufEntry; 1],
}

impl SelectedBuf<'_> {
    /// The operation moved `bytes` bytes through the buffer. Returns whether
    /// the buffer is left part-used and will be handed out again under the
    /// same id. # C: O(N_groups)
    pub fn consume(&mut self, bytes: u64) -> bool {
        self.inode.reg.lock().commit_group(self.gid, &self.entry, 1, bytes)
    }
}

/// Look at the head buffer of the group the SQE names. # C: O(N_groups)
pub fn select_buf<'a>(inode: &'a IoUringInode, gid: u16) -> Result<SelectedBuf<'a>, i64> {
    let peek = inode.reg.lock().peek_group(gid, 1).map_err(err)?;
    let e = peek.entries[0];
    Ok(SelectedBuf { buf: ProvidedBuf { addr: e.addr, len: e.len, bid: e.bid },
                     inode, gid, entry: [e] })
}
