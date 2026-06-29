// sys_io_uring_register (NR_IO_URING_REGISTER=427) per docs/53§0 —
// per-syscall-file ABI shim. Real Linux registration semantics: fixed
// buffers, fixed files, completion eventfd, and the feature probe. All
// state lives on the ring's IoUringInode (crate::io_uring::IoUringReg);
// this file only parses/validates and calls into that state.
//
// Opcodes (Linux uapi enum io_uring_register_op):
//   0 REGISTER_BUFFERS     1 UNREGISTER_BUFFERS
//   2 REGISTER_FILES       3 UNREGISTER_FILES
//   4 REGISTER_EVENTFD     5 UNREGISTER_EVENTFD
//   6 REGISTER_FILES_UPDATE
//   8 REGISTER_PROBE
// Any other opcode → EINVAL (Linux rejects unknown register opcodes).

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::{File, InodeRef};

use crate::io_uring::{
    IoUringInode, IORING_MAX_REG, IORING_OP_ACCEPT, IORING_OP_CLOSE,
    IORING_OP_CONNECT, IORING_OP_FSYNC, IORING_OP_NOP, IORING_OP_OPENAT,
    IORING_OP_READ, IORING_OP_READV, IORING_OP_READ_FIXED, IORING_OP_RECV,
    IORING_OP_SEND, IORING_OP_WRITE, IORING_OP_WRITEV, IORING_OP_WRITE_FIXED,
};

const IORING_REGISTER_BUFFERS:       u32 = 0;
const IORING_UNREGISTER_BUFFERS:     u32 = 1;
const IORING_REGISTER_FILES:         u32 = 2;
const IORING_UNREGISTER_FILES:       u32 = 3;
const IORING_REGISTER_EVENTFD:       u32 = 4;
const IORING_UNREGISTER_EVENTFD:     u32 = 5;
const IORING_REGISTER_FILES_UPDATE:  u32 = 6;
const IORING_REGISTER_PROBE:         u32 = 8;

/// io_uring_probe_op.flags bit: opcode is supported.
const IO_URING_OP_SUPPORTED: u16 = 1 << 0;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_io_uring_register(fd, opcode, arg, nr_args)` — slot 427.
/// # C: O(nr_args)
pub fn sys_io_uring_register(args: &syscall::SyscallArgs) -> i64 {
    let fd      = args.a0 as i32;
    let opcode  = args.a1 as u32;
    let arg     = args.a2;
    let nr_args = args.a3 as u32;

    let inode_ref = match ring_inode(fd) { Ok(i) => i, Err(e) => return e };
    // Backend state lives in `i_private` post-KEYSTONE; the ino tag check in
    // `ring_inode` already confirmed this is an io_uring inode.
    let inode = match inode_ref.private::<IoUringInode>() {
        Some(d) => d, None => return err(Errno::Einval),
    };

    match opcode {
        IORING_REGISTER_BUFFERS      => register_buffers(inode, arg, nr_args),
        IORING_UNREGISTER_BUFFERS    => unregister_buffers(inode),
        IORING_REGISTER_FILES        => register_files(inode, arg, nr_args),
        IORING_UNREGISTER_FILES      => unregister_files(inode),
        IORING_REGISTER_FILES_UPDATE => files_update(inode, arg, nr_args),
        IORING_REGISTER_EVENTFD      => register_eventfd(inode, arg),
        IORING_UNREGISTER_EVENTFD    => unregister_eventfd(inode),
        IORING_REGISTER_PROBE        => register_probe(inode, arg, nr_args),
        _ => err(Errno::Einval),
    }
}

/// Resolve a ring fd to its io_uring `InodeRef` (verifying the io_uring ino
/// tag). The backend `IoUringInode` is recovered via `inode.private()`.
/// # C: O(1)
fn ring_inode(fd: i32) -> Result<InodeRef, i64> {
    let cur = match sched::live::current() { Some(c) => c, None => return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for io_uring_register fd resolution.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return Err(err(Errno::Ebadf)) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return Err(err(Errno::Ebadf)) };
    if (file.inode().ino() & 0xFFFF_FFFF_0000_0000) != 0x494F_5552_0000_0000 {
        return Err(err(Errno::Einval));
    }
    Ok(file.inode().clone())
}

/// Validate a user pointer + length lie below USER_VA_END. # C: O(1)
fn user_range_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END
        && ptr.checked_add(len).map(|e| e <= hal::USER_VA_END).unwrap_or(false)
}

/// IORING_REGISTER_BUFFERS: arg → struct iovec[nr_args]. # C: O(nr_args)
fn register_buffers(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    if nr == 0 || nr > IORING_MAX_REG { return err(Errno::Einval); }
    if !user_range_ok(arg, nr as u64 * 16) { return err(Errno::Efault); }
    { if inode.reg.lock().buffers.is_some() { return err(Errno::Ebusy); } }
    let mut v: Vec<(u64, u64)> = Vec::with_capacity(nr as usize);
    for i in 0..nr as u64 {
        let p = arg + i * 16;
        // SAFETY: range [arg, arg+nr*16) validated < USER_VA_END; struct iovec is {base:u64, len:u64}; CPL=0 read through caller's AS.
        let (base, len) = unsafe {
            (core::ptr::read_volatile(p as *const u64),
             core::ptr::read_volatile((p + 8) as *const u64))
        };
        if len == 0 || !user_range_ok(base, len) { return err(Errno::Efault); }
        v.push((base, len));
    }
    inode.reg.lock().buffers = Some(v);
    0
}

/// IORING_UNREGISTER_BUFFERS. # C: O(1)
fn unregister_buffers(inode: &IoUringInode) -> i64 {
    let mut g = inode.reg.lock();
    if g.buffers.take().is_none() { return err(Errno::Enxio); }
    0
}

/// Resolve a raw fd (or -1 empty slot) to an Arc<File>. # C: O(1)
fn resolve_fd(fdt: &Arc<vfs::FdTable>, raw: i32) -> Result<Option<Arc<File>>, i64> {
    if raw < 0 { return Ok(None); }
    match fdt.get(raw) { Ok(f) => Ok(Some(f)), Err(_) => Err(err(Errno::Ebadf)) }
}

/// Read nr_args s32 fds from `arg`. # C: O(nr_args)
fn read_fds(fdt: &Arc<vfs::FdTable>, arg: u64, nr: u32) -> Result<Vec<Option<Arc<File>>>, i64> {
    if !user_range_ok(arg, nr as u64 * 4) { return Err(err(Errno::Efault)); }
    let mut v: Vec<Option<Arc<File>>> = Vec::with_capacity(nr as usize);
    for i in 0..nr as u64 {
        // SAFETY: range [arg, arg+nr*4) validated < USER_VA_END; reading the s32 fd array entries through the caller's AS at CPL=0.
        let raw = unsafe { core::ptr::read_volatile((arg + i * 4) as *const i32) };
        v.push(resolve_fd(fdt, raw)?);
    }
    Ok(v)
}

/// Current task's fd table. # C: O(1)
fn cur_fdt() -> Result<Arc<vfs::FdTable>, i64> {
    let cur = match sched::live::current() { Some(c) => c, None => return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for io_uring fixed-file registration.
    match unsafe { cur.fd_table_ref() } { Some(t) => Ok(t.clone()), None => Err(err(Errno::Ebadf)) }
}

/// IORING_REGISTER_FILES. # C: O(nr_args)
fn register_files(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    if nr == 0 || nr > IORING_MAX_REG { return err(Errno::Einval); }
    { if inode.reg.lock().files.is_some() { return err(Errno::Ebusy); } }
    let fdt = match cur_fdt() { Ok(t) => t, Err(e) => return e };
    let v = match read_fds(&fdt, arg, nr) { Ok(v) => v, Err(e) => return e };
    inode.reg.lock().files = Some(v);
    0
}

/// IORING_UNREGISTER_FILES. # C: O(1)
fn unregister_files(inode: &IoUringInode) -> i64 {
    let mut g = inode.reg.lock();
    if g.files.take().is_none() { return err(Errno::Enxio); }
    0
}

/// IORING_REGISTER_FILES_UPDATE: arg → struct io_uring_rsrc_update
/// {offset:u32, resv:u32, data:u64 ptr-to-fds}. Replaces nr_args slots
/// starting at `offset`. # C: O(nr_args)
fn files_update(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    if nr == 0 { return err(Errno::Einval); }
    if !user_range_ok(arg, 16) { return err(Errno::Efault); }
    // SAFETY: arg validated < USER_VA_END; struct io_uring_rsrc_update is 16 bytes {offset:u32, resv:u32, data:u64}; CPL=0 read of caller's AS.
    let (offset, data) = unsafe {
        (core::ptr::read_volatile(arg as *const u32),
         core::ptr::read_volatile((arg + 8) as *const u64))
    };
    let fdt = match cur_fdt() { Ok(t) => t, Err(e) => return e };
    let updates = match read_fds(&fdt, data, nr) { Ok(v) => v, Err(e) => return e };
    let mut g = inode.reg.lock();
    let files = match g.files.as_mut() { Some(f) => f, None => return err(Errno::Enxio) };
    let end = match (offset as usize).checked_add(nr as usize) { Some(e) => e, None => return err(Errno::Einval) };
    if end > files.len() { return err(Errno::Einval); }
    for (i, u) in updates.into_iter().enumerate() { files[offset as usize + i] = u; }
    0
}

/// IORING_REGISTER_EVENTFD: arg → single s32 eventfd. # C: O(1)
fn register_eventfd(inode: &IoUringInode, arg: u64) -> i64 {
    if !user_range_ok(arg, 4) { return err(Errno::Efault); }
    // SAFETY: arg validated < USER_VA_END; reading the single eventfd s32 through the caller's AS at CPL=0.
    let raw = unsafe { core::ptr::read_volatile(arg as *const i32) };
    let fdt = match cur_fdt() { Ok(t) => t, Err(e) => return e };
    let file = match fdt.get(raw) { Ok(f) => f, Err(_) => return err(Errno::Ebadf) };
    let mut g = inode.reg.lock();
    if g.eventfd.is_some() { return err(Errno::Ebusy); }
    g.eventfd = Some(file);
    0
}

/// IORING_UNREGISTER_EVENTFD. # C: O(1)
fn unregister_eventfd(inode: &IoUringInode) -> i64 {
    let mut g = inode.reg.lock();
    if g.eventfd.take().is_none() { return err(Errno::Enxio); }
    0
}

/// IORING_REGISTER_PROBE: arg → struct io_uring_probe + nr ops slots.
/// Header: last_op u8@0, ops_len u8@1, resv u16@2, resv2[3] u32@4..16;
/// ops[] start @16 (each io_uring_probe_op = 8 bytes: op u8, resv u8,
/// flags u16, resv2 u32). # C: O(nr)
fn register_probe(inode: &IoUringInode, arg: u64, nr: u32) -> i64 {
    let _ = inode;
    if nr == 0 { return err(Errno::Einval); }
    let total = 16u64 + nr as u64 * 8;
    if !user_range_ok(arg, total) { return err(Errno::Efault); }
    // Highest opcode dispatch_op handles (RECV=27); ops_len = entries filled.
    let last_op: u8 = IORING_OP_RECV;
    // SAFETY: range [arg, arg+16+nr*8) validated < USER_VA_END; writing struct io_uring_probe header + ops[] through caller's AS at CPL=0.
    unsafe {
        core::ptr::write_volatile(arg as *mut u8, last_op);
        core::ptr::write_volatile((arg + 1) as *mut u8, nr as u8);
        core::ptr::write_volatile((arg + 2) as *mut u16, 0);
        for i in 0..nr as u64 {
            let p = arg + 16 + i * 8;
            let op = i as u8;
            let flags = if op_supported(op) { IO_URING_OP_SUPPORTED } else { 0 };
            core::ptr::write_volatile(p as *mut u8, op);           // op
            core::ptr::write_volatile((p + 1) as *mut u8, 0);      // resv
            core::ptr::write_volatile((p + 2) as *mut u16, flags); // flags
            core::ptr::write_volatile((p + 4) as *mut u32, 0);     // resv2
        }
    }
    0
}

/// Whether dispatch_op actually executes this opcode. # C: O(1)
fn op_supported(op: u8) -> bool {
    matches!(op,
        IORING_OP_NOP | IORING_OP_READV | IORING_OP_WRITEV | IORING_OP_FSYNC
        | IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED | IORING_OP_ACCEPT
        | IORING_OP_CONNECT | IORING_OP_OPENAT | IORING_OP_CLOSE
        | IORING_OP_READ | IORING_OP_WRITE | IORING_OP_SEND | IORING_OP_RECV)
}
