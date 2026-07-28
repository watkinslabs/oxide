// sys_io_uring_register (NR_IO_URING_REGISTER=427) per docs/53§0 — ABI shim
// only: decode the opcode/arguments (`io_uring_abi::register_op::decode`),
// resolve the ring fd, call exactly one work fn in `io_uring::register`.
//
// Linux: `io_uring/register.c` `SYSCALL_DEFINE4(io_uring_register)` →
// `__io_uring_register()`; `io_uring/io_uring.c` `io_uring_ctx_get_file()`.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use crate::io_uring::{ring_of, IoUringInode};
use crate::io_uring::register as work;
use crate::io_uring_abi::register_op::{decode, registered_ring_error, RegisterOp};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_io_uring_register(fd, opcode, arg, nr_args)` — slot 427.
/// # C: O(nr_args)
pub fn sys_io_uring_register(args: &syscall::SyscallArgs) -> i64 {
    let fd      = args.a0 as i32;
    let opcode  = args.a1 as u32;
    let arg     = args.a2;
    let nr_args = args.a3 as u32;

    let req = match decode(opcode, fd, arg, nr_args) { Ok(r) => r, Err(e) => return err(e) };
    // IORING_REGISTER_USE_REGISTERED_RING indexes the task's registered-ring
    // array, which stays empty without IORING_REGISTER_RING_FDS.
    if req.registered_ring { return err(registered_ring_error(fd)); }

    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for io_uring_register fd resolution.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return err(Errno::Ebadf) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return err(Errno::Ebadf) };
    // Linux io_uring_ctx_get_file(): EOPNOTSUPP, not EINVAL, for an fd that is
    // not an io_uring instance.
    let inode_ref = match ring_of(&file) { Ok(i) => i, Err(e) => return err(e) };
    let inode: &IoUringInode = match inode_ref.private::<IoUringInode>() {
        Some(d) => d, None => return err(Errno::Eopnotsupp),
    };

    match req.op {
        RegisterOp::Buffers { arg, nr }     => work::buffers(inode, arg, nr),
        RegisterOp::UnregisterBuffers       => work::unregister_buffers(inode),
        RegisterOp::Files { arg, nr }       => work::files(inode, arg, nr),
        RegisterOp::UnregisterFiles         => work::unregister_files(inode),
        RegisterOp::FilesUpdate { arg, nr } => work::files_update(inode, arg, nr),
        RegisterOp::Eventfd { arg, async_only } => work::eventfd(inode, arg, async_only),
        RegisterOp::UnregisterEventfd       => work::unregister_eventfd(inode),
        RegisterOp::Probe { arg, nr }       => work::probe(arg, nr),
    }
}
