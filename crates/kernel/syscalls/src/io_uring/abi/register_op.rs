// `io_uring_register(2)` opcode + argument ladder.
//
// The ladder is three stages, in this order: strip the
// `USE_REGISTERED_RING` selector bit, bound the opcode, then split the
// "blind" (`fd == -1`) forms from the ring forms. Only then are the
// per-opcode argument rules applied. Getting that order wrong is what made
// every valid opcode carrying the selector bit look like an unknown opcode.

use syscall::errno::Errno;

/// `enum io_uring_register_op`.
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
/// Largest registered-ring array.
pub const IO_RINGFD_REG_MAX: u32 = 16;
/// Largest registered-buffer table.
pub const IORING_MAX_REG_BUFFERS: u32 = 1 << 14;
/// Largest registered-file table.
pub const IORING_MAX_FIXED_FILES: u32 = 1 << 20;
/// `IORING_REGISTER_PROBE` caps its op count at 256.
pub const PROBE_MAX_OPS: u32 = 256;
/// `sizeof(struct io_uring_rsrc_update)` — {offset:u32, resv:u32, data:u64}.
pub const RSRC_UPDATE_BYTES: u64 = 16;
/// `sizeof(struct io_uring_rsrc_update2)` — adds {tags:u64, nr:u32, resv2:u32}.
pub const RSRC_UPDATE2_BYTES: u64 = 32;
/// `sizeof(struct io_uring_rsrc_register)` — {nr:u32, flags:u32, resv2:u64,
/// data:u64, tags:u64}.
pub const RSRC_REGISTER_BYTES: u64 = 32;
/// `sizeof(struct iovec)` on a 64-bit ABI.
pub const IOVEC_BYTES: u64 = 16;
/// `io_uring_probe` header bytes; `ops[]` follows.
pub const PROBE_HDR_BYTES: u64 = 16;
/// `sizeof(struct io_uring_probe_op)`.
pub const PROBE_OP_BYTES: u64 = 8;
/// `io_uring_probe_op.flags` bit `IO_URING_OP_SUPPORTED`.
pub const IO_URING_OP_SUPPORTED: u16 = 1 << 0;
/// `sizeof(struct io_uring_file_index_range)`.
pub const FILE_INDEX_RANGE_BYTES: u64 = 16;
/// `sizeof(struct io_uring_clock_register)`.
pub const CLOCK_REGISTER_BYTES: u64 = 16;
/// `sizeof(struct io_uring_clone_buffers)`.
pub const CLONE_BUFFERS_BYTES: u64 = 32;
/// `sizeof(struct io_uring_buf_status)`.
pub const BUF_STATUS_BYTES: u64 = 40;
/// `sizeof(struct io_uring_sync_cancel_reg)`.
pub const SYNC_CANCEL_BYTES: u64 = 64;
/// `sizeof(struct io_uring_buf_reg)`.
pub const BUF_REG_BYTES: u64 = 40;

/// A register request that will be executed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegisterOp {
    Buffers { arg: u64, nr: u32 },
    UnregisterBuffers,
    Files { arg: u64, nr: u32 },
    UnregisterFiles,
    FilesUpdate { arg: u64, nr: u32 },
    /// `async_only` distinguishes `IORING_REGISTER_EVENTFD_ASYNC`.
    Eventfd { arg: u64, async_only: bool },
    UnregisterEventfd,
    Probe { arg: u64, nr: u32 },
    Personality,
    UnregisterPersonality { id: u32 },
    Restrictions { arg: u64, nr: u32 },
    EnableRings,
    /// Tagged registration; `buffers` picks the resource kind.
    Rsrc { arg: u64, nr: u32, buffers: bool },
    /// Tagged update; `buffers` picks the resource kind.
    RsrcUpdate { arg: u64, nr: u32, buffers: bool },
    FileAllocRange { arg: u64 },
    Clock { arg: u64 },
    CloneBuffers { arg: u64 },
    PbufRing { arg: u64 },
    UnregisterPbufRing { arg: u64 },
    PbufStatus { arg: u64 },
    SyncCancel { arg: u64 },
    Query { arg: u64, nr: u32 },
    SendMsgRing { arg: u64 },
}

/// A decoded `io_uring_register(2)` call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Request {
    pub registered_ring: bool,
    /// The opcode with the selector bit stripped — the register-restriction
    /// allow-list is keyed on this.
    pub opcode: u32,
    pub op: RegisterOp,
}

/// Opcodes this kernel recognises but cannot execute, each because a whole
/// mechanism it needs is absent — a worker pool, a per-task registered-ring
/// array, multi-frame ring regions, a zero-copy receive queue, busy-poll, or
/// a BPF program loader. `EOPNOTSUPP` says "recognised, not supported"; a
/// zero would tell the caller its registration took effect. # C: O(1)
fn unsupported(_opcode: u32) -> Errno { Errno::Eopnotsupp }

/// Per-opcode argument ladder. # C: O(1)
fn ring_op(opcode: u32, arg: u64, nr_args: u32) -> Result<RegisterOp, Errno> {
    let no_args = |op: RegisterOp| -> Result<RegisterOp, Errno> {
        if arg != 0 || nr_args != 0 { Err(Errno::Einval) } else { Ok(op) }
    };
    let one = |op: RegisterOp| -> Result<RegisterOp, Errno> {
        if arg == 0 || nr_args != 1 { Err(Errno::Einval) } else { Ok(op) }
    };
    match opcode {
        IORING_REGISTER_BUFFERS => {
            if arg == 0 { return Err(Errno::Efault); }
            Ok(RegisterOp::Buffers { arg, nr: nr_args })
        }
        IORING_UNREGISTER_BUFFERS => no_args(RegisterOp::UnregisterBuffers),
        IORING_REGISTER_FILES => {
            if arg == 0 { return Err(Errno::Efault); }
            Ok(RegisterOp::Files { arg, nr: nr_args })
        }
        IORING_UNREGISTER_FILES => no_args(RegisterOp::UnregisterFiles),
        IORING_REGISTER_FILES_UPDATE => Ok(RegisterOp::FilesUpdate { arg, nr: nr_args }),
        IORING_REGISTER_EVENTFD => {
            if nr_args != 1 { return Err(Errno::Einval); }
            Ok(RegisterOp::Eventfd { arg, async_only: false })
        }
        IORING_REGISTER_EVENTFD_ASYNC => {
            if nr_args != 1 { return Err(Errno::Einval); }
            Ok(RegisterOp::Eventfd { arg, async_only: true })
        }
        IORING_UNREGISTER_EVENTFD => no_args(RegisterOp::UnregisterEventfd),
        IORING_REGISTER_PROBE => {
            if arg == 0 || nr_args > PROBE_MAX_OPS { return Err(Errno::Einval); }
            Ok(RegisterOp::Probe { arg, nr: nr_args })
        }
        IORING_REGISTER_PERSONALITY => no_args(RegisterOp::Personality),
        IORING_UNREGISTER_PERSONALITY => {
            // The id travels in `nr_args`, so only `arg` must be empty.
            if arg != 0 { return Err(Errno::Einval); }
            Ok(RegisterOp::UnregisterPersonality { id: nr_args })
        }
        IORING_REGISTER_ENABLE_RINGS => no_args(RegisterOp::EnableRings),
        IORING_REGISTER_RESTRICTIONS => Ok(RegisterOp::Restrictions { arg, nr: nr_args }),
        IORING_REGISTER_FILES2 => Ok(RegisterOp::Rsrc { arg, nr: nr_args, buffers: false }),
        IORING_REGISTER_BUFFERS2 => Ok(RegisterOp::Rsrc { arg, nr: nr_args, buffers: true }),
        IORING_REGISTER_FILES_UPDATE2 => Ok(RegisterOp::RsrcUpdate { arg, nr: nr_args, buffers: false }),
        IORING_REGISTER_BUFFERS_UPDATE => Ok(RegisterOp::RsrcUpdate { arg, nr: nr_args, buffers: true }),
        IORING_REGISTER_FILE_ALLOC_RANGE => {
            if arg == 0 || nr_args != 0 { return Err(Errno::Einval); }
            Ok(RegisterOp::FileAllocRange { arg })
        }
        IORING_REGISTER_CLOCK => {
            if arg == 0 || nr_args != 0 { return Err(Errno::Einval); }
            Ok(RegisterOp::Clock { arg })
        }
        IORING_REGISTER_CLONE_BUFFERS => one(RegisterOp::CloneBuffers { arg }),
        IORING_REGISTER_PBUF_RING => one(RegisterOp::PbufRing { arg }),
        IORING_UNREGISTER_PBUF_RING => one(RegisterOp::UnregisterPbufRing { arg }),
        IORING_REGISTER_PBUF_STATUS => one(RegisterOp::PbufStatus { arg }),
        IORING_REGISTER_SYNC_CANCEL => one(RegisterOp::SyncCancel { arg }),
        IORING_REGISTER_QUERY => Ok(RegisterOp::Query { arg, nr: nr_args }),
        IORING_REGISTER_SEND_MSG_RING => one(RegisterOp::SendMsgRing { arg }),
        _ => Err(unsupported(opcode)),
    }
}

/// `fd == -1` ("blind") registration: the forms that need no ring. Every
/// other opcode is `EINVAL` there, because the missing ring is an argument
/// error rather than a missing feature. # C: O(1)
fn blind(opcode: u32, arg: u64, nr_args: u32) -> Result<RegisterOp, Errno> {
    match opcode {
        IORING_REGISTER_SEND_MSG_RING => {
            if arg == 0 || nr_args != 1 { return Err(Errno::Einval); }
            Ok(RegisterOp::SendMsgRing { arg })
        }
        IORING_REGISTER_QUERY => Ok(RegisterOp::Query { arg, nr: nr_args }),
        IORING_REGISTER_RESTRICTIONS | IORING_REGISTER_BPF_FILTER => Err(unsupported(opcode)),
        _ => Err(Errno::Einval),
    }
}

/// Syscall-level decode. # C: O(1)
pub fn decode(raw_opcode: u32, fd: i32, arg: u64, nr_args: u32) -> Result<Request, Errno> {
    let registered_ring = raw_opcode & IORING_REGISTER_USE_REGISTERED_RING != 0;
    let opcode = raw_opcode & !IORING_REGISTER_USE_REGISTERED_RING;
    if opcode >= IORING_REGISTER_LAST { return Err(Errno::Einval); }
    if fd == -1 {
        return Ok(Request { registered_ring, opcode, op: blind(opcode, arg, nr_args)? });
    }
    Ok(Request { registered_ring, opcode, op: ring_op(opcode, arg, nr_args)? })
}

/// Resolving `fd` through the task's registered-ring array. No
/// `IORING_REGISTER_RING_FDS` is executed, so every slot is empty: past the
/// array is `EINVAL`, an empty slot inside it is `EBADF`. # C: O(1)
pub fn registered_ring_error(fd: i32) -> Errno {
    if fd < 0 || fd as u32 >= IO_RINGFD_REG_MAX { Errno::Einval } else { Errno::Ebadf }
}

/// Buffer-registration admission: EBUSY before the count check. # C: O(1)
pub fn buffers_admission(already_registered: bool, nr: u32) -> Result<(), Errno> {
    if already_registered { return Err(Errno::Ebusy); }
    if nr == 0 || nr > IORING_MAX_REG_BUFFERS { return Err(Errno::Einval); }
    Ok(())
}

/// File-registration admission: EBUSY, then the zero check, then the two
/// EMFILE bounds (the fixed-file ceiling, then `RLIMIT_NOFILE`). # C: O(1)
pub fn files_admission(already_registered: bool, nr: u32, nofile_soft: u32) -> Result<(), Errno> {
    if already_registered { return Err(Errno::Ebusy); }
    if nr == 0 { return Err(Errno::Einval); }
    if nr > IORING_MAX_FIXED_FILES || nr > nofile_soft { return Err(Errno::Emfile); }
    Ok(())
}

/// Update admission. `registered` is `None` when nothing is registered.
/// # C: O(1)
pub fn files_update_admission(registered: Option<u32>, offset: u32, nr: u32) -> Result<(), Errno> {
    if nr == 0 { return Err(Errno::Einval); }
    let len = match registered { Some(l) => l, None => return Err(Errno::Enxio) };
    let end = offset.checked_add(nr).ok_or(Errno::Eoverflow)?;
    if end > len { return Err(Errno::Einval); }
    Ok(())
}

/// `io_probe` CLAMPS its op count instead of failing. # C: O(1)
pub fn probe_ops(nr: u32, op_count: u32) -> u32 { if nr > op_count { op_count } else { nr } }

#[cfg(test)]
#[path = "register_op/tests.rs"]
mod tests;
