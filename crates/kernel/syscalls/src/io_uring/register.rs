// `io_uring_register(2)` op implementations. The slot file decodes the opcode
// and arguments (`io_uring_abi::register_op::decode`) and calls exactly one of
// these (docs/53).
//
// Linux reference: `io_uring/rsrc.c` io_sqe_buffers_register(),
// io_sqe_files_register(), io_register_files_update(), __io_sqe_files_update();
// `io_uring/register.c` io_probe(); `io_uring/eventfd.c` io_eventfd_register().

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::File;

use crate::io_uring_abi::ops::{op_supported, OP_COUNT};
use crate::io_uring_abi::register_op::*;
use super::ring::IoUringInode;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Current task's fd table. # C: O(1)
fn cur_fdt() -> Result<Arc<vfs::FdTable>, i64> {
    let cur = match sched::live::current() { Some(c) => c, None => return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for io_uring registration.
    match unsafe { cur.fd_table_ref() } { Some(t) => Ok(t.clone()), None => Err(err(Errno::Ebadf)) }
}

/// `RLIMIT_NOFILE` soft limit, the second `EMFILE` bound Linux applies to
/// `IORING_REGISTER_FILES`. # C: O(1)
fn nofile_soft() -> u32 {
    sched::live::current().map(|c| c.nofile_soft().min(u32::MAX as usize) as u32).unwrap_or(0)
}

/// Read one `struct iovec` from user memory. # C: O(1)
fn read_iovec(p: u64) -> Result<(u64, u64), i64> {
    let mut b = [0u8; IOVEC_BYTES as usize];
    if uaccess::copy_from_user(&mut b, p).is_err() { return Err(err(Errno::Efault)); }
    let base = u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let len  = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    // Linux io_sqe_buffer_register(): a NULL base with a zero length is an
    // empty slot; a NULL base with a length is EFAULT.
    if base == 0 { return if len == 0 { Ok((0, 0)) } else { Err(err(Errno::Efault)) }; }
    if len > uaccess::MAX_RW_COUNT as u64 { return Err(err(Errno::Einval)); }
    if !uaccess::access_ok(base, len as usize) { return Err(err(Errno::Efault)); }
    Ok((base, len))
}

/// `IORING_REGISTER_BUFFERS`. # C: O(nr)
pub fn buffers(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    let already = inode.reg.lock().buffers.is_some();
    if let Err(e) = buffers_admission(already, nr) { return err(e); }
    let mut v: Vec<(u64, u64)> = Vec::with_capacity(nr as usize);
    for i in 0..nr as u64 {
        match read_iovec(arg + i * IOVEC_BYTES) { Ok(iov) => v.push(iov), Err(e) => return e }
    }
    inode.reg.lock().buffers = Some(v);
    0
}

/// `IORING_UNREGISTER_BUFFERS`. # C: O(1)
pub fn unregister_buffers(inode: &IoUringInode) -> i64 {
    if inode.reg.lock().buffers.take().is_none() { return err(Errno::Enxio); }
    0
}

/// Resolve one registered-file slot. Linux refuses to register an io_uring
/// instance as a fixed file (`io_is_uring_fops` → `EBADF`), which is what
/// stops a ring from pinning itself. `-1` is the sparse empty slot. # C: O(1)
fn resolve_slot(fdt: &Arc<vfs::FdTable>, raw: i32) -> Result<Option<Arc<File>>, i64> {
    if raw < 0 { return Ok(None); }
    let f = match fdt.get(raw) { Ok(f) => f, Err(_) => return Err(err(Errno::Ebadf)) };
    crate::io_uring_identity::admit_fixed_file(&f).map_err(err)?;
    Ok(Some(f))
}

/// Read one `__s32` fd from the user array. # C: O(1)
fn read_fd(p: u64) -> Result<i32, i64> {
    let mut b = [0u8; 4];
    if uaccess::copy_from_user(&mut b, p).is_err() { return Err(err(Errno::Efault)); }
    Ok(i32::from_ne_bytes(b))
}

/// `IORING_REGISTER_FILES`. # C: O(nr)
pub fn files(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    let already = inode.reg.lock().files.is_some();
    if let Err(e) = files_admission(already, nr, nofile_soft()) { return err(e); }
    let fdt = match cur_fdt() { Ok(t) => t, Err(e) => return e };
    let mut v: Vec<Option<Arc<File>>> = Vec::with_capacity(nr as usize);
    for i in 0..nr as u64 {
        let raw = match read_fd(arg + i * 4) { Ok(r) => r, Err(e) => return e };
        match resolve_slot(&fdt, raw) { Ok(s) => v.push(s), Err(e) => return e }
    }
    inode.reg.lock().files = Some(v);
    0
}

/// `IORING_UNREGISTER_FILES`. # C: O(1)
pub fn unregister_files(inode: &IoUringInode) -> i64 {
    if inode.reg.lock().files.take().is_none() { return err(Errno::Enxio); }
    0
}

/// `IORING_REGISTER_FILES_UPDATE`: `arg` → `struct io_uring_rsrc_update`
/// {offset:u32, resv:u32, data:u64 → __s32 fds[nr]}. Returns the number of
/// slots processed, as Linux `__io_sqe_files_update` does. # C: O(nr)
pub fn files_update(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    if nr == 0 { return err(Errno::Einval); }
    let mut b = [0u8; RSRC_UPDATE_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let offset = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    let resv   = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
    let data   = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    if resv != 0 { return err(Errno::Einval); }

    let len = inode.reg.lock().files.as_ref().map(|f| f.len() as u32);
    if let Err(e) = files_update_admission(len, offset, nr) { return err(e); }

    let fdt = match cur_fdt() { Ok(t) => t, Err(e) => return e };
    let mut updates: Vec<(usize, Option<Arc<File>>)> = Vec::with_capacity(nr as usize);
    for i in 0..nr as u64 {
        let raw = match read_fd(data + i * 4) { Ok(r) => r, Err(e) => return e };
        // IORING_REGISTER_FILES_SKIP leaves the slot as it is.
        if raw == IORING_REGISTER_FILES_SKIP { continue; }
        match resolve_slot(&fdt, raw) {
            Ok(s)  => updates.push((offset as usize + i as usize, s)),
            Err(e) => return e,
        }
    }
    let mut g = inode.reg.lock();
    let table = match g.files.as_mut() { Some(f) => f, None => return err(Errno::Enxio) };
    for (at, slot) in updates { table[at] = slot; }
    nr as i64
}

/// `IORING_REGISTER_EVENTFD` / `IORING_REGISTER_EVENTFD_ASYNC`: `arg` → one
/// `__s32` eventfd. # C: O(1)
pub fn eventfd(inode: &IoUringInode, arg: u64, async_only: bool) -> i64 {
    let raw = match read_fd(arg) { Ok(r) => r, Err(e) => return e };
    let fdt = match cur_fdt() { Ok(t) => t, Err(e) => return e };
    let file = match fdt.get(raw) { Ok(f) => f, Err(_) => return err(Errno::Ebadf) };
    let mut g = inode.reg.lock();
    if g.eventfd.is_some() { return err(Errno::Ebusy); }
    g.eventfd = Some(file);
    g.eventfd_async = async_only;
    0
}

/// `IORING_UNREGISTER_EVENTFD`. # C: O(1)
pub fn unregister_eventfd(inode: &IoUringInode) -> i64 {
    let mut g = inode.reg.lock();
    if g.eventfd.take().is_none() { return err(Errno::Enxio); }
    g.eventfd_async = false;
    0
}

/// `IORING_REGISTER_PROBE`: `arg` → `struct io_uring_probe` + `nr` ops slots.
/// Header: last_op u8@0, ops_len u8@1, resv u16@2, resv2[3] u32@4..16; ops[]
/// at 16, each `struct io_uring_probe_op` = {op u8, resv u8, flags u16,
/// resv2 u32}. Linux `io_probe()` clamps `nr_args` to the opcode count,
/// requires the caller's buffer to be all-zero, and copies the whole image
/// back. # C: O(nr)
pub fn probe(arg: u64, nr: u32) -> i64 {
    // Linux clamps nr_args BEFORE computing `size`, so only the clamped image
    // is ever read or written — a caller that passes 256 but sized its buffer
    // for the real opcode count is not faulted.
    let ops = probe_ops(nr, OP_COUNT);
    let total = (PROBE_HDR_BYTES + ops as u64 * PROBE_OP_BYTES) as usize;
    // Read the caller's image first: Linux memdup_user()s it and rejects a
    // non-zero byte anywhere (`memchr_inv`), so a caller cannot smuggle
    // pre-set fields past the probe.
    let mut img: Vec<u8> = Vec::new();
    if img.try_reserve_exact(total).is_err() { return err(Errno::Enomem); }
    img.resize(total, 0);
    if uaccess::copy_from_user(&mut img[..], arg).is_err() { return err(Errno::Efault); }
    if img.iter().any(|&b| b != 0) { return err(Errno::Einval); }

    img[0] = (OP_COUNT - 1) as u8;   // last_op
    img[1] = ops as u8;              // ops_len
    for i in 0..ops as usize {
        let at = PROBE_HDR_BYTES as usize + i * PROBE_OP_BYTES as usize;
        img[at] = i as u8;
        let flags = if op_supported(i as u8) { IO_URING_OP_SUPPORTED } else { 0 };
        img[at + 2..at + 4].copy_from_slice(&flags.to_ne_bytes());
    }
    if uaccess::copy_to_user(arg, &img[..]).is_err() { return err(Errno::Efault); }
    0
}
