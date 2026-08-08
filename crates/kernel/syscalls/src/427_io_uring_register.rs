// sys_io_uring_register (NR_IO_URING_REGISTER=427) per docs/53§0 — ABI shim
// only: decode the opcode and arguments, resolve the ring, check the ring's
// own register allow-list, call exactly one work function.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::register as work;
use crate::io_uring::{ring_ctx, ring_of};
use crate::io_uring_abi::register_op::{decode, registered_ring_error, RegisterOp,
                                       RSRC_REGISTER_BYTES, RSRC_UPDATE2_BYTES,
                                       CLONE_BUFFERS_BYTES};
use crate::io_uring_abi::uapi::IORING_SETUP_R_DISABLED;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Resolve a ring fd. # C: O(1)
fn ring_for(fd: i32) -> Result<Arc<IoUringInode>, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
    let file = match fdt.clone().get(fd) { Ok(f) => f, Err(_) => return Err(err(Errno::Ebadf)) };
    let inode = ring_of(&file).map_err(err)?;
    ring_ctx(&inode).ok_or(err(Errno::Eopnotsupp))
}

/// `struct io_uring_rsrc_register` — {nr, flags, resv2, data, tags}.
/// # C: O(1)
fn read_rsrc_register(arg: u64) -> Result<(u32, u64, u64), i64> {
    let mut b = [0u8; RSRC_REGISTER_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return Err(err(Errno::Efault)); }
    let nr    = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    let flags = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
    let resv2 = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    let data  = u64::from_ne_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]);
    let tags  = u64::from_ne_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]);
    if flags != 0 || resv2 != 0 { return Err(err(Errno::Einval)); }
    Ok((nr, data, tags))
}

/// `struct io_uring_rsrc_update2` — {offset, resv, data, tags, nr, resv2}.
/// # C: O(1)
fn read_rsrc_update2(arg: u64) -> Result<(u32, u64, u64, u32), i64> {
    let mut b = [0u8; RSRC_UPDATE2_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return Err(err(Errno::Efault)); }
    let offset = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
    let resv   = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
    let data   = u64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    let tags   = u64::from_ne_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]);
    let nr     = u32::from_ne_bytes([b[24], b[25], b[26], b[27]]);
    let resv2  = u32::from_ne_bytes([b[28], b[29], b[30], b[31]]);
    if resv != 0 || resv2 != 0 { return Err(err(Errno::Einval)); }
    Ok((offset, data, tags, nr))
}

/// `IORING_REGISTER_CLONE_BUFFERS`. # C: O(nr)
fn clone_buffers(inode: &IoUringInode, arg: u64) -> i64 {
    let mut b = [0u8; CLONE_BUFFERS_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let g32 = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let src_fd = g32(0); let flags = g32(4);
    let src_off = g32(8); let dst_off = g32(12); let nr = g32(16);
    if flags != 0 || b[20..].iter().any(|&x| x != 0) { return err(Errno::Einval); }
    let src = match ring_for(src_fd as i32) { Ok(s) => s, Err(e) => return e };
    work::buffers::clone_from(inode, &src, src_off, dst_off, nr)
}

/// Run one decoded request against a resolved ring. # C: per opcode
fn run(inode: &Arc<IoUringInode>, op: RegisterOp) -> i64 {
    match op {
        RegisterOp::Buffers { arg, nr }     => work::buffers::register(inode, arg, nr),
        RegisterOp::UnregisterBuffers       => work::buffers::unregister(inode),
        RegisterOp::Files { arg, nr }       => work::files::register(inode, arg, nr),
        RegisterOp::UnregisterFiles         => work::files::unregister(inode),
        RegisterOp::FilesUpdate { arg, nr } => work::files::update(inode, arg, nr),
        RegisterOp::Eventfd { arg, async_only } => work::eventfd::register(inode, arg, async_only),
        RegisterOp::UnregisterEventfd       => work::eventfd::unregister(inode),
        RegisterOp::Probe { arg, nr }       => work::probe::probe(arg, nr),
        RegisterOp::Query { arg, nr }       => work::probe::query(arg, nr),
        RegisterOp::Personality             => work::rings::personality(inode),
        RegisterOp::UnregisterPersonality { id } => work::rings::unregister_personality(inode, id),
        RegisterOp::Restrictions { arg, nr }=> work::rings::restrictions(inode, arg, nr),
        RegisterOp::EnableRings             => work::rings::enable_rings(inode),
        RegisterOp::Clock { arg }           => work::rings::clock(inode, arg),
        RegisterOp::SyncCancel { arg }      => work::rings::sync_cancel(inode, arg),
        RegisterOp::PbufStatus { arg }      => work::rings::pbuf_status(inode, arg),
        RegisterOp::FileAllocRange { arg }  => work::files::alloc_range(inode, arg),
        RegisterOp::CloneBuffers { arg }    => clone_buffers(inode, arg),
        RegisterOp::Rsrc { arg, nr, buffers } => {
            if arg == 0 { return err(Errno::Einval); }
            let (count, data, tags) = match read_rsrc_register(arg) { Ok(v) => v, Err(e) => return e };
            if nr != 1 { return err(Errno::Einval); }
            if buffers { work::buffers::register_tagged(inode, data, count, tags) }
            else       { work::files::register_tagged(inode, data, count, tags) }
        }
        RegisterOp::RsrcUpdate { arg, nr, buffers } => {
            if arg == 0 || nr != 1 { return err(Errno::Einval); }
            let (offset, data, tags, count) = match read_rsrc_update2(arg) { Ok(v) => v, Err(e) => return e };
            if count == 0 { return err(Errno::Einval); }
            if buffers { work::buffers::update(inode, offset, data, tags, count) }
            else       { work::files::update_tagged(inode, offset, data, tags, count) }
        }
        RegisterOp::SendMsgRing { arg }     => work::rings::send_msg_ring(arg),
        RegisterOp::PbufRing { arg }        => work::pbuf::register(inode, arg),
        RegisterOp::UnregisterPbufRing { arg } => work::pbuf::unregister(inode, arg),
    }
}

/// `sys_io_uring_register(fd, opcode, arg, nr_args)` — slot 427.
/// # C: O(nr_args)
pub fn sys_io_uring_register(args: &syscall::SyscallArgs) -> i64 {
    let fd      = args.a0 as i32;
    let opcode  = args.a1 as u32;
    let arg     = args.a2;
    let nr_args = args.a3 as u32;

    let req = match decode(opcode, fd, arg, nr_args) { Ok(r) => r, Err(e) => return err(e) };
    // The registered-ring selector indexes the task's registered-ring array,
    // which stays empty without a ring-fd registration.
    if req.registered_ring { return err(registered_ring_error(fd)); }
    if fd == -1 {
        // The blind forms take no ring at all.
        return match req.op {
            RegisterOp::Query { arg, nr }   => work::probe::query(arg, nr),
            RegisterOp::SendMsgRing { arg } => work::rings::send_msg_ring(arg),
            _ => err(Errno::Einval),
        };
    }

    let inode = match ring_for(fd) { Ok(i) => i, Err(e) => return e };
    if let Err(e) = inode.claim_issuer() { return err(e); }
    // A ring's own register allow-list, once it is enabled.
    if inode.flags & IORING_SETUP_R_DISABLED == 0 || !inode.test_state(crate::io_uring::ctx::state::DISABLED) {
        if !inode.reg.lock().restrictions.allows_register(req.opcode) { return err(Errno::Eacces); }
    }
    run(&inode, req.op)
}
