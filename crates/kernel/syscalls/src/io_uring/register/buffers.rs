// Registered buffers: pinning, tagged registration, updates, and cloning.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::pin::PinnedRange;
use crate::io_uring::rsrc::RegBuf;
use crate::io_uring_abi::register_op::*;

use super::tags;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read one `struct iovec` and pin the range it names. A null base with a
/// zero length is the legal empty slot; a null base with a length is EFAULT.
/// # C: O(len / PAGE)
fn pin_iovec(p: u64) -> Result<PinnedRange, i64> {
    let mut b = [0u8; IOVEC_BYTES as usize];
    if uaccess::copy_from_user(&mut b, p).is_err() { return Err(err(Errno::Efault)); }
    let base = u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let len  = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    if base == 0 {
        return if len == 0 { PinnedRange::pin(0, 0).map_err(err) } else { Err(err(Errno::Efault)) };
    }
    if len > uaccess::MAX_RW_COUNT as u64 { return Err(err(Errno::Einval)); }
    if !uaccess::access_ok(base, len as usize) { return Err(err(Errno::Efault)); }
    PinnedRange::pin(base, len).map_err(err)
}

/// Pin `nr` buffers from a user iovec array, with optional tags. # C: O(bytes)
fn pin_table(arg: u64, nr: u32, tags_ptr: u64) -> Result<Vec<RegBuf>, i64> {
    let mut v: Vec<RegBuf> = Vec::new();
    if v.try_reserve_exact(nr as usize).is_err() { return Err(err(Errno::Enomem)); }
    for i in 0..nr as u64 {
        let buf = pin_iovec(arg + i * IOVEC_BYTES)?;
        let tag = if tags_ptr == 0 { 0 } else { read_tag(tags_ptr + i * 8)? };
        v.push(RegBuf { buf: Arc::new(buf), tag });
    }
    Ok(v)
}

/// # C: O(1)
pub fn read_tag(p: u64) -> Result<u64, i64> {
    let mut b = [0u8; 8];
    if uaccess::copy_from_user(&mut b, p).is_err() { return Err(err(Errno::Efault)); }
    Ok(u64::from_ne_bytes(b))
}

/// `IORING_REGISTER_BUFFERS`. # C: O(bytes)
pub fn register(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    register_tagged(inode, arg, nr, 0)
}

/// Shared body of the plain and tagged registrations. # C: O(bytes)
pub fn register_tagged(inode: &IoUringInode, arg: u64, nr: u32, tags_ptr: u64) -> i64 {
    let already = inode.reg.lock().buffers.is_some();
    if let Err(e) = buffers_admission(already, nr) { return err(e); }
    let table = match pin_table(arg, nr, tags_ptr) { Ok(t) => t, Err(e) => return e };
    inode.reg.lock().buffers = Some(table);
    0
}

/// `IORING_UNREGISTER_BUFFERS`: every tagged slot notifies as it goes.
/// # C: O(N_buffers)
pub fn unregister(inode: &IoUringInode) -> i64 {
    let table = inode.reg.lock().buffers.take();
    let Some(table) = table else { return err(Errno::Enxio) };
    for slot in table.iter() { tags::release(inode, slot.tag); }
    0
}

/// `IORING_REGISTER_BUFFERS_UPDATE`: replace `nr` slots from `offset`, each
/// with a freshly pinned range, notifying whatever the slots held.
/// # C: O(bytes)
pub fn update(inode: &IoUringInode, offset: u32, data: u64, tags_ptr: u64, nr: u32) -> i64 {
    let len = inode.reg.lock().buffers_len();
    if let Err(e) = files_update_admission(len, offset, nr) { return err(e); }
    let fresh = match pin_table(data, nr, tags_ptr) { Ok(t) => t, Err(e) => return e };
    let mut released: Vec<u64> = Vec::new();
    if released.try_reserve_exact(nr as usize).is_err() { return err(Errno::Enomem); }
    {
        let mut g = inode.reg.lock();
        let Some(table) = g.buffers.as_mut() else { return err(Errno::Enxio) };
        for (i, slot) in fresh.into_iter().enumerate() {
            let at = offset as usize + i;
            released.push(table[at].tag);
            table[at] = slot;
        }
    }
    for tag in released { tags::release(inode, tag); }
    nr as i64
}

/// `IORING_REGISTER_CLONE_BUFFERS`: take another ring's registered buffers.
/// The clone SHARES the pinned frames — the memory is pinned once, however
/// many rings name it. # C: O(nr)
pub fn clone_from(inode: &IoUringInode, src: &IoUringInode, src_off: u32, dst_off: u32, nr: u32)
    -> i64
{
    if core::ptr::eq(inode, src) { return err(Errno::Ebadf); }
    let src_table = {
        let g = src.reg.lock();
        let Some(t) = g.buffers.as_ref() else { return err(Errno::Enxio) };
        let take = if nr == 0 { t.len() as u32 } else { nr };
        let end = match src_off.checked_add(take) { Some(e) => e, None => return err(Errno::Eoverflow) };
        if end as usize > t.len() { return err(Errno::Einval); }
        let mut v: Vec<Arc<PinnedRange>> = Vec::new();
        if v.try_reserve_exact(take as usize).is_err() { return err(Errno::Enomem); }
        for i in src_off..end { v.push(Arc::clone(&t[i as usize].buf)); }
        v
    };
    let mut g = inode.reg.lock();
    match g.buffers.as_mut() {
        None => {
            if dst_off != 0 { return err(Errno::Einval); }
            let mut v: Vec<RegBuf> = Vec::new();
            if v.try_reserve_exact(src_table.len()).is_err() { return err(Errno::Enomem); }
            for b in src_table { v.push(RegBuf { buf: b, tag: 0 }); }
            g.buffers = Some(v);
        }
        Some(dst) => {
            let end = dst_off as usize + src_table.len();
            if end > dst.len() { return err(Errno::Einval); }
            for (i, b) in src_table.into_iter().enumerate() {
                dst[dst_off as usize + i] = RegBuf { buf: b, tag: 0 };
            }
        }
    }
    0
}
