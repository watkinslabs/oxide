// Registered files: registration, updates, and the direct-descriptor window.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::File;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::rsrc::RegFile;
use crate::io_uring_abi::register_op::*;

use super::tags;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Current task's descriptor table. # C: O(1)
fn cur_fdt() -> Result<Arc<vfs::FdTable>, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot for io_uring registration.
    match unsafe { cur.fd_table_ref() } { Some(t) => Ok(t.clone()), None => Err(err(Errno::Ebadf)) }
}

/// `RLIMIT_NOFILE` soft limit — the second EMFILE bound. # C: O(1)
fn nofile_soft() -> u32 {
    sched::live::current().map(|c| c.nofile_soft().min(u32::MAX as usize) as u32).unwrap_or(0)
}

/// Resolve one slot. A ring may not be registered as a fixed file, which is
/// what stops a ring from pinning itself. `-1` is the sparse empty slot.
/// # C: O(1)
fn resolve_slot(fdt: &Arc<vfs::FdTable>, raw: i32) -> Result<Option<Arc<File>>, i64> {
    if raw < 0 { return Ok(None); }
    let f = match fdt.get(raw) { Ok(f) => f, Err(_) => return Err(err(Errno::Ebadf)) };
    crate::io_uring_identity::admit_fixed_file(&f).map_err(err)?;
    Ok(Some(f))
}

/// Read one `__s32` descriptor from a user array. # C: O(1)
fn read_fd(p: u64) -> Result<i32, i64> {
    let mut b = [0u8; 4];
    if uaccess::copy_from_user(&mut b, p).is_err() { return Err(err(Errno::Efault)); }
    Ok(i32::from_ne_bytes(b))
}

/// `IORING_REGISTER_FILES`. # C: O(nr)
pub fn register(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    register_tagged(inode, arg, nr, 0)
}

/// Shared body of the plain and tagged registrations. # C: O(nr)
pub fn register_tagged(inode: &IoUringInode, arg: u64, nr: u32, tags_ptr: u64) -> i64 {
    let already = inode.reg.lock().files.is_some();
    if let Err(e) = files_admission(already, nr, nofile_soft()) { return err(e); }
    let fdt = match cur_fdt() { Ok(t) => t, Err(e) => return e };
    let mut v: Vec<RegFile> = Vec::new();
    if v.try_reserve_exact(nr as usize).is_err() { return err(Errno::Enomem); }
    for i in 0..nr as u64 {
        let raw = match read_fd(arg + i * 4) { Ok(r) => r, Err(e) => return e };
        let file = match resolve_slot(&fdt, raw) { Ok(s) => s, Err(e) => return e };
        let tag = if tags_ptr == 0 { 0 } else {
            match super::buffers::read_tag(tags_ptr + i * 8) { Ok(t) => t, Err(e) => return e }
        };
        v.push(RegFile { file, tag });
    }
    inode.reg.lock().files = Some(v);
    0
}

/// `IORING_UNREGISTER_FILES`: every tagged slot notifies as it goes.
/// # C: O(N_files)
pub fn unregister(inode: &IoUringInode) -> i64 {
    let table = inode.reg.lock().files.take();
    let Some(table) = table else { return err(Errno::Enxio) };
    for slot in table.iter() { tags::release(inode, slot.tag); }
    0
}

/// `IORING_REGISTER_FILES_UPDATE`: `arg` is a `struct io_uring_rsrc_update`.
/// # C: O(nr)
pub fn update(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    if nr == 0 { return err(Errno::Einval); }
    let mut b = [0u8; RSRC_UPDATE_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let offset = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    let resv   = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
    let data   = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    if resv != 0 { return err(Errno::Einval); }
    update_tagged(inode, offset, data, 0, nr)
}

/// The update body shared by the register opcodes and `IORING_OP_FILES_UPDATE`.
/// # C: O(nr)
pub fn update_tagged(inode: &IoUringInode, offset: u32, data: u64, tags_ptr: u64, nr: u32) -> i64 {
    let len = inode.reg.lock().files_len();
    if let Err(e) = files_update_admission(len, offset, nr) { return err(e); }
    let fdt = match cur_fdt() { Ok(t) => t, Err(e) => return e };
    let mut updates: Vec<(usize, RegFile)> = Vec::new();
    if updates.try_reserve_exact(nr as usize).is_err() { return err(Errno::Enomem); }
    for i in 0..nr as u64 {
        let raw = match read_fd(data + i * 4) { Ok(r) => r, Err(e) => return e };
        // A skip entry leaves the slot exactly as it is, tag included.
        if raw == IORING_REGISTER_FILES_SKIP { continue; }
        let file = match resolve_slot(&fdt, raw) { Ok(s) => s, Err(e) => return e };
        let tag = if tags_ptr == 0 { 0 } else {
            match super::buffers::read_tag(tags_ptr + i * 8) { Ok(t) => t, Err(e) => return e }
        };
        updates.push((offset as usize + i as usize, RegFile { file, tag }));
    }
    let mut released: Vec<u64> = Vec::new();
    if released.try_reserve_exact(updates.len()).is_err() { return err(Errno::Enomem); }
    {
        let mut g = inode.reg.lock();
        let Some(table) = g.files.as_mut() else { return err(Errno::Enxio) };
        for (at, slot) in updates {
            released.push(table[at].tag);
            table[at] = slot;
        }
    }
    for tag in released { tags::release(inode, tag); }
    nr as i64
}

/// The `IORING_OP_FILES_UPDATE` entry point — the same work, from an SQE.
/// # C: O(nr)
pub fn update_slots(inode: &IoUringInode, fds: u64, nr: u32, offset: u32) -> i64 {
    if nr == 0 { return err(Errno::Einval); }
    update_tagged(inode, offset, fds, 0, nr)
}

/// `IORING_REGISTER_FILE_ALLOC_RANGE`: bound the slot window automatic
/// direct-descriptor allocation may use. # C: O(1)
pub fn alloc_range(inode: &IoUringInode, arg: u64) -> i64 {
    let mut b = [0u8; FILE_INDEX_RANGE_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let off = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    let len = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
    let resv = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    if resv != 0 { return err(Errno::Einval); }
    let end = match off.checked_add(len) { Some(e) => e, None => return err(Errno::Eoverflow) };
    let mut g = inode.reg.lock();
    let Some(table_len) = g.files_len() else { return err(Errno::Enxio) };
    if end > table_len { return err(Errno::Einval); }
    g.alloc_range = (off, len);
    0
}
