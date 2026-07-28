// `io_uring_register(2)` opcode + argument ladder.
//
// Linux reference, read for every rule below:
//   io_uring/register.c  SYSCALL_DEFINE4(io_uring_register) — USE_REGISTERED_RING
//                        masking, the `>= IORING_REGISTER_LAST` bound, `fd == -1`
//   io_uring/register.c  __io_uring_register()  — the per-opcode arg/nr_args ladder
//   io_uring/register.c  io_uring_register_blind()
//   io_uring/register.c  io_probe()
//   io_uring/io_uring.c  io_uring_ctx_get_file() — EBADF / EOPNOTSUPP
//   io_uring/rsrc.c      io_sqe_buffers_register(), io_sqe_files_register(),
//                        io_register_files_update(), __io_sqe_files_update()

use syscall::errno::Errno;

/// `enum io_uring_register_op` (Linux `include/uapi/linux/io_uring.h`).
pub const IORING_REGISTER_BUFFERS:           u32 = 0;
pub const IORING_UNREGISTER_BUFFERS:         u32 = 1;
pub const IORING_REGISTER_FILES:             u32 = 2;
pub const IORING_UNREGISTER_FILES:           u32 = 3;
pub const IORING_REGISTER_EVENTFD:           u32 = 4;
pub const IORING_UNREGISTER_EVENTFD:         u32 = 5;
pub const IORING_REGISTER_FILES_UPDATE:      u32 = 6;
pub const IORING_REGISTER_EVENTFD_ASYNC:     u32 = 7;
pub const IORING_REGISTER_PROBE:             u32 = 8;
pub const IORING_REGISTER_PERSONALITY:       u32 = 9;
pub const IORING_UNREGISTER_PERSONALITY:     u32 = 10;
pub const IORING_REGISTER_RESTRICTIONS:      u32 = 11;
pub const IORING_REGISTER_ENABLE_RINGS:      u32 = 12;
pub const IORING_REGISTER_FILES2:            u32 = 13;
pub const IORING_REGISTER_FILES_UPDATE2:     u32 = 14;
pub const IORING_REGISTER_BUFFERS2:          u32 = 15;
pub const IORING_REGISTER_BUFFERS_UPDATE:    u32 = 16;
pub const IORING_REGISTER_IOWQ_AFF:          u32 = 17;
pub const IORING_UNREGISTER_IOWQ_AFF:        u32 = 18;
pub const IORING_REGISTER_IOWQ_MAX_WORKERS:  u32 = 19;
pub const IORING_REGISTER_RING_FDS:          u32 = 20;
pub const IORING_UNREGISTER_RING_FDS:        u32 = 21;
pub const IORING_REGISTER_PBUF_RING:         u32 = 22;
pub const IORING_UNREGISTER_PBUF_RING:       u32 = 23;
pub const IORING_REGISTER_SYNC_CANCEL:       u32 = 24;
pub const IORING_REGISTER_FILE_ALLOC_RANGE:  u32 = 25;
pub const IORING_REGISTER_PBUF_STATUS:       u32 = 26;
pub const IORING_REGISTER_NAPI:              u32 = 27;
pub const IORING_UNREGISTER_NAPI:            u32 = 28;
pub const IORING_REGISTER_CLOCK:             u32 = 29;
pub const IORING_REGISTER_CLONE_BUFFERS:     u32 = 30;
pub const IORING_REGISTER_SEND_MSG_RING:     u32 = 31;
pub const IORING_REGISTER_ZCRX_IFQ:          u32 = 32;
pub const IORING_REGISTER_RESIZE_RINGS:      u32 = 33;
pub const IORING_REGISTER_MEM_REGION:        u32 = 34;
pub const IORING_REGISTER_QUERY:             u32 = 35;
pub const IORING_REGISTER_ZCRX_CTRL:         u32 = 36;
pub const IORING_REGISTER_BPF_FILTER:        u32 = 37;
/// One past the last defined opcode; `opcode >= LAST` is `EINVAL`.
pub const IORING_REGISTER_LAST:              u32 = 38;
/// Opcode flag: `fd` is an index into the task's registered-ring array.
pub const IORING_REGISTER_USE_REGISTERED_RING: u32 = 1 << 31;

/// `IORING_REGISTER_FILES_SKIP` — leave this update slot untouched.
pub const IORING_REGISTER_FILES_SKIP: i32 = -2;
/// `IO_RINGFD_REG_MAX` (Linux `include/linux/io_uring_types.h`).
pub const IO_RINGFD_REG_MAX: u32 = 16;
/// `IORING_MAX_REG_BUFFERS` (Linux `io_uring/rsrc.c`).
pub const IORING_MAX_REG_BUFFERS: u32 = 1 << 14;
/// `IORING_MAX_FIXED_FILES` (Linux `io_uring/rsrc.c`).
pub const IORING_MAX_FIXED_FILES: u32 = 1 << 20;
/// `io_uring_register(2)` caps `IORING_REGISTER_PROBE` at 256 ops.
pub const PROBE_MAX_OPS: u32 = 256;
/// `sizeof(struct io_uring_rsrc_update)` — {offset:u32, resv:u32, data:u64}.
pub const RSRC_UPDATE_BYTES: u64 = 16;
/// `sizeof(struct iovec)` on a 64-bit ABI.
pub const IOVEC_BYTES: u64 = 16;
/// `io_uring_probe` header bytes; `ops[]` follows.
pub const PROBE_HDR_BYTES: u64 = 16;
/// `sizeof(struct io_uring_probe_op)`.
pub const PROBE_OP_BYTES: u64 = 8;
/// `io_uring_probe_op.flags` bit `IO_URING_OP_SUPPORTED`.
pub const IO_URING_OP_SUPPORTED: u16 = 1 << 0;

/// A register request oxide executes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegisterOp {
    Buffers { arg: u64, nr: u32 },
    UnregisterBuffers,
    Files { arg: u64, nr: u32 },
    UnregisterFiles,
    FilesUpdate { arg: u64, nr: u32 },
    /// `async_only` distinguishes `IORING_REGISTER_EVENTFD_ASYNC`, which
    /// signals only for completions posted from async context.
    Eventfd { arg: u64, async_only: bool },
    UnregisterEventfd,
    Probe { arg: u64, nr: u32 },
}

/// A decoded `io_uring_register(2)` call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Request { pub registered_ring: bool, pub op: RegisterOp }

/// Opcodes Linux defines that oxide does not execute. `EOPNOTSUPP` says
/// "recognised, not supported" — the answer Linux itself uses when an
/// io_uring path is reached with the wrong kind of object. Returning 0 here
/// would be worse than any error: the caller would believe its buffers /
/// personalities / restrictions took effect. # C: O(1)
fn unimplemented(opcode: u32) -> Errno {
    let _ = opcode;
    Errno::Eopnotsupp
}

/// Per-opcode argument ladder, in Linux `__io_uring_register` order.
/// # C: O(1)
fn ring_op(opcode: u32, arg: u64, nr_args: u32) -> Result<RegisterOp, Errno> {
    match opcode {
        IORING_REGISTER_BUFFERS => {
            if arg == 0 { return Err(Errno::Efault); }
            Ok(RegisterOp::Buffers { arg, nr: nr_args })
        }
        IORING_UNREGISTER_BUFFERS => {
            if arg != 0 || nr_args != 0 { return Err(Errno::Einval); }
            Ok(RegisterOp::UnregisterBuffers)
        }
        IORING_REGISTER_FILES => {
            if arg == 0 { return Err(Errno::Efault); }
            Ok(RegisterOp::Files { arg, nr: nr_args })
        }
        IORING_UNREGISTER_FILES => {
            if arg != 0 || nr_args != 0 { return Err(Errno::Einval); }
            Ok(RegisterOp::UnregisterFiles)
        }
        IORING_REGISTER_FILES_UPDATE => Ok(RegisterOp::FilesUpdate { arg, nr: nr_args }),
        IORING_REGISTER_EVENTFD => {
            if nr_args != 1 { return Err(Errno::Einval); }
            Ok(RegisterOp::Eventfd { arg, async_only: false })
        }
        IORING_REGISTER_EVENTFD_ASYNC => {
            if nr_args != 1 { return Err(Errno::Einval); }
            Ok(RegisterOp::Eventfd { arg, async_only: true })
        }
        IORING_UNREGISTER_EVENTFD => {
            if arg != 0 || nr_args != 0 { return Err(Errno::Einval); }
            Ok(RegisterOp::UnregisterEventfd)
        }
        IORING_REGISTER_PROBE => {
            if arg == 0 || nr_args > PROBE_MAX_OPS { return Err(Errno::Einval); }
            Ok(RegisterOp::Probe { arg, nr: nr_args })
        }
        _ => Err(unimplemented(opcode)),
    }
}

/// `fd == -1` ("blind") registration: Linux routes four opcodes that need no
/// ring, and rejects every other opcode with `EINVAL`
/// (`io_uring_register_blind`). oxide implements none of the four.
/// # C: O(1)
fn blind(opcode: u32) -> Errno {
    match opcode {
        IORING_REGISTER_SEND_MSG_RING | IORING_REGISTER_QUERY
        | IORING_REGISTER_RESTRICTIONS | IORING_REGISTER_BPF_FILTER => unimplemented(opcode),
        _ => Errno::Einval,
    }
}

/// Syscall-level decode: strip `IORING_REGISTER_USE_REGISTERED_RING`, bound
/// the opcode, split the blind path, then validate the arguments.
/// # C: O(1)
pub fn decode(raw_opcode: u32, fd: i32, arg: u64, nr_args: u32) -> Result<Request, Errno> {
    let registered_ring = raw_opcode & IORING_REGISTER_USE_REGISTERED_RING != 0;
    let opcode = raw_opcode & !IORING_REGISTER_USE_REGISTERED_RING;
    if opcode >= IORING_REGISTER_LAST { return Err(Errno::Einval); }
    if fd == -1 { return Err(blind(opcode)); }
    Ok(Request { registered_ring, op: ring_op(opcode, arg, nr_args)? })
}

/// Resolving `fd` through the task's registered-ring array. oxide implements
/// no `IORING_REGISTER_RING_FDS`, so every slot is empty: Linux
/// `io_uring_ctx_get_file(registered = true)` gives `EINVAL` past the array
/// and `EBADF` for an empty slot. # C: O(1)
pub fn registered_ring_error(fd: i32) -> Errno {
    if fd < 0 || fd as u32 >= IO_RINGFD_REG_MAX { Errno::Einval } else { Errno::Ebadf }
}

/// `io_sqe_buffers_register` admission: EBUSY before the count check.
/// # C: O(1)
pub fn buffers_admission(already_registered: bool, nr: u32) -> Result<(), Errno> {
    if already_registered { return Err(Errno::Ebusy); }
    if nr == 0 || nr > IORING_MAX_REG_BUFFERS { return Err(Errno::Einval); }
    Ok(())
}

/// `io_sqe_files_register` admission: EBUSY, then the zero check, then the
/// two EMFILE bounds (`IORING_MAX_FIXED_FILES`, then `RLIMIT_NOFILE`).
/// # C: O(1)
pub fn files_admission(already_registered: bool, nr: u32, nofile_soft: u32) -> Result<(), Errno> {
    if already_registered { return Err(Errno::Ebusy); }
    if nr == 0 { return Err(Errno::Einval); }
    if nr > IORING_MAX_FIXED_FILES || nr > nofile_soft { return Err(Errno::Emfile); }
    Ok(())
}

/// `io_register_files_update` + `__io_sqe_files_update` admission.
/// `registered` is `None` when no `IORING_REGISTER_FILES` has been done.
/// # C: O(1)
pub fn files_update_admission(registered: Option<u32>, offset: u32, nr: u32) -> Result<(), Errno> {
    if nr == 0 { return Err(Errno::Einval); }
    let len = match registered { Some(l) => l, None => return Err(Errno::Enxio) };
    let end = offset.checked_add(nr).ok_or(Errno::Eoverflow)?;
    if end > len { return Err(Errno::Einval); }
    Ok(())
}

/// `io_probe`: Linux CLAMPS `nr_args` to the opcode count instead of failing.
/// # C: O(1)
pub fn probe_ops(nr: u32, op_count: u32) -> u32 { if nr > op_count { op_count } else { nr } }

#[cfg(test)]
#[path = "register_op/tests.rs"]
mod tests;
