// `IORING_OP_*` / `IOSQE_*` and which opcodes the submission engine runs.
// `IORING_REGISTER_PROBE` reports exactly the executed set, so it must not
// drift from `dispatch::dispatch_op`.

pub const IORING_OP_NOP:             u8 = 0;
pub const IORING_OP_READV:           u8 = 1;
pub const IORING_OP_WRITEV:          u8 = 2;
pub const IORING_OP_FSYNC:           u8 = 3;
pub const IORING_OP_READ_FIXED:      u8 = 4;
pub const IORING_OP_WRITE_FIXED:     u8 = 5;
pub const IORING_OP_POLL_ADD:        u8 = 6;
pub const IORING_OP_POLL_REMOVE:     u8 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: u8 = 8;
pub const IORING_OP_SENDMSG:         u8 = 9;
pub const IORING_OP_RECVMSG:         u8 = 10;
pub const IORING_OP_TIMEOUT:         u8 = 11;
pub const IORING_OP_TIMEOUT_REMOVE:  u8 = 12;
pub const IORING_OP_ACCEPT:          u8 = 13;
pub const IORING_OP_ASYNC_CANCEL:    u8 = 14;
pub const IORING_OP_LINK_TIMEOUT:    u8 = 15;
pub const IORING_OP_CONNECT:         u8 = 16;
pub const IORING_OP_FALLOCATE:       u8 = 17;
pub const IORING_OP_OPENAT:          u8 = 18;
pub const IORING_OP_CLOSE:           u8 = 19;
pub const IORING_OP_FILES_UPDATE:    u8 = 20;
pub const IORING_OP_STATX:           u8 = 21;
pub const IORING_OP_READ:            u8 = 22;
pub const IORING_OP_WRITE:           u8 = 23;
pub const IORING_OP_FADVISE:         u8 = 24;
pub const IORING_OP_MADVISE:         u8 = 25;
pub const IORING_OP_SEND:            u8 = 26;
pub const IORING_OP_RECV:            u8 = 27;
pub const IORING_OP_OPENAT2:         u8 = 28;
pub const IORING_OP_EPOLL_CTL:       u8 = 29;
pub const IORING_OP_SPLICE:          u8 = 30;
pub const IORING_OP_PROVIDE_BUFFERS: u8 = 31;
pub const IORING_OP_REMOVE_BUFFERS:  u8 = 32;
pub const IORING_OP_TEE:             u8 = 33;
pub const IORING_OP_SHUTDOWN:        u8 = 34;
pub const IORING_OP_RENAMEAT:        u8 = 35;
pub const IORING_OP_UNLINKAT:        u8 = 36;
pub const IORING_OP_MKDIRAT:         u8 = 37;
pub const IORING_OP_SYMLINKAT:       u8 = 38;
pub const IORING_OP_LINKAT:          u8 = 39;
pub const IORING_OP_MSG_RING:        u8 = 40;
pub const IORING_OP_FSETXATTR:       u8 = 41;
pub const IORING_OP_SETXATTR:        u8 = 42;
pub const IORING_OP_FGETXATTR:       u8 = 43;
pub const IORING_OP_GETXATTR:        u8 = 44;
pub const IORING_OP_SOCKET:          u8 = 45;
pub const IORING_OP_URING_CMD:       u8 = 46;
pub const IORING_OP_SEND_ZC:         u8 = 47;
pub const IORING_OP_SENDMSG_ZC:      u8 = 48;
pub const IORING_OP_READ_MULTISHOT:  u8 = 49;
pub const IORING_OP_WAITID:          u8 = 50;
pub const IORING_OP_FUTEX_WAIT:      u8 = 51;
pub const IORING_OP_FUTEX_WAKE:      u8 = 52;
pub const IORING_OP_FUTEX_WAITV:     u8 = 53;
pub const IORING_OP_FIXED_FD_INSTALL: u8 = 54;
pub const IORING_OP_FTRUNCATE:       u8 = 55;
pub const IORING_OP_BIND:            u8 = 56;
pub const IORING_OP_LISTEN:          u8 = 57;
pub const IORING_OP_RECV_ZC:         u8 = 58;
pub const IORING_OP_EPOLL_WAIT:      u8 = 59;
pub const IORING_OP_READV_FIXED:     u8 = 60;
pub const IORING_OP_WRITEV_FIXED:    u8 = 61;
pub const IORING_OP_PIPE:            u8 = 62;
pub const IORING_OP_NOP128:          u8 = 63;
pub const IORING_OP_URING_CMD128:    u8 = 64;
/// One past the last defined opcode. An SQE naming anything at or past this is
/// `EINVAL`; `io_uring_probe` reports `last_op = OP_LAST - 1`.
pub const OP_LAST: u8 = 65;

/// `IOSQE_FIXED_FILE` — SQE `fd` is an index into the registered-files array.
pub const IOSQE_FIXED_FILE:       u8 = 1 << 0;
/// `IOSQE_IO_DRAIN` — start only once every earlier request has completed.
pub const IOSQE_IO_DRAIN:         u8 = 1 << 1;
/// `IOSQE_IO_LINK` — the next SQE runs only if this one succeeds.
pub const IOSQE_IO_LINK:          u8 = 1 << 2;
/// `IOSQE_IO_HARDLINK` — the next SQE runs whatever this one returns.
pub const IOSQE_IO_HARDLINK:      u8 = 1 << 3;
/// `IOSQE_ASYNC` — issue from a worker rather than inline.
pub const IOSQE_ASYNC:            u8 = 1 << 4;
/// `IOSQE_BUFFER_SELECT` — take the target buffer from a provided-buffer group.
pub const IOSQE_BUFFER_SELECT:    u8 = 1 << 5;
/// `IOSQE_CQE_SKIP_SUCCESS` — post no completion when the op succeeds.
pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

/// Every defined SQE flag; a bit outside this mask is `EINVAL`.
pub const SQE_VALID_FLAGS: u8 =
    IOSQE_FIXED_FILE | IOSQE_IO_DRAIN | IOSQE_IO_LINK | IOSQE_IO_HARDLINK
    | IOSQE_ASYNC | IOSQE_BUFFER_SELECT | IOSQE_CQE_SKIP_SUCCESS;

/// The two flags that make an SQE the head of a chain.
pub const SQE_LINK_FLAGS: u8 = IOSQE_IO_LINK | IOSQE_IO_HARDLINK;

/// `IORING_FSYNC_DATASYNC` — `IORING_OP_FSYNC`'s flag selecting `fdatasync`.
pub const IORING_FSYNC_DATASYNC: u32 = 1 << 0;

/// `IORING_CQE_F_BUFFER` — the CQE's upper flag half carries a buffer id.
pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
/// `IORING_CQE_F_MORE` — more completions will follow for this SQE.
pub const IORING_CQE_F_MORE: u32 = 1 << 1;
/// Bit position of the buffer id inside `cqe->flags`.
pub const IORING_CQE_BUFFER_SHIFT: u32 = 16;

/// Whether the submission engine executes this opcode. # C: O(1)
pub fn op_supported(op: u8) -> bool {
    matches!(op,
        IORING_OP_NOP | IORING_OP_READV | IORING_OP_WRITEV | IORING_OP_FSYNC
        | IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED | IORING_OP_ACCEPT
        | IORING_OP_CONNECT | IORING_OP_OPENAT | IORING_OP_CLOSE
        | IORING_OP_READ | IORING_OP_WRITE | IORING_OP_SEND | IORING_OP_RECV
        | IORING_OP_SENDMSG | IORING_OP_RECVMSG | IORING_OP_SYNC_FILE_RANGE
        | IORING_OP_FALLOCATE | IORING_OP_STATX | IORING_OP_FADVISE
        | IORING_OP_MADVISE | IORING_OP_OPENAT2 | IORING_OP_EPOLL_CTL
        | IORING_OP_TEE | IORING_OP_SHUTDOWN
        | IORING_OP_RENAMEAT | IORING_OP_UNLINKAT | IORING_OP_MKDIRAT
        | IORING_OP_SYMLINKAT | IORING_OP_LINKAT | IORING_OP_FSETXATTR
        | IORING_OP_SETXATTR | IORING_OP_FGETXATTR | IORING_OP_GETXATTR
        | IORING_OP_SOCKET | IORING_OP_FTRUNCATE | IORING_OP_BIND
        | IORING_OP_LISTEN | IORING_OP_PIPE
        | IORING_OP_FILES_UPDATE | IORING_OP_MSG_RING
        | IORING_OP_PROVIDE_BUFFERS | IORING_OP_REMOVE_BUFFERS
        | IORING_OP_FIXED_FD_INSTALL
        | IORING_OP_TIMEOUT | IORING_OP_TIMEOUT_REMOVE | IORING_OP_LINK_TIMEOUT
        | IORING_OP_ASYNC_CANCEL | IORING_OP_POLL_ADD | IORING_OP_POLL_REMOVE)
}

/// Whether the opcode reads its data through a provided-buffer group when the
/// SQE carries `IOSQE_BUFFER_SELECT`. # C: O(1)
pub fn op_buffer_select(op: u8) -> bool {
    matches!(op, IORING_OP_READ | IORING_OP_READV | IORING_OP_RECV | IORING_OP_RECVMSG)
}

#[cfg(test)]
#[path = "ops/tests.rs"]
mod tests;
