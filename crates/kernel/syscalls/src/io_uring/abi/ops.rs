// `IORING_OP_*` / `IOSQE_*` (Linux `include/uapi/linux/io_uring.h`,
// `enum io_uring_op`) and which opcodes oxide's synchronous dispatcher runs.
// `IORING_REGISTER_PROBE` reports exactly this set, so it must not drift from
// `dispatch::dispatch_op`.

pub const IORING_OP_NOP:          u8 = 0;
pub const IORING_OP_READV:        u8 = 1;
pub const IORING_OP_WRITEV:       u8 = 2;
pub const IORING_OP_FSYNC:        u8 = 3;
pub const IORING_OP_READ_FIXED:   u8 = 4;
pub const IORING_OP_WRITE_FIXED:  u8 = 5;
pub const IORING_OP_POLL_ADD:     u8 = 6;
pub const IORING_OP_POLL_REMOVE:  u8 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: u8 = 8;
pub const IORING_OP_SENDMSG:      u8 = 9;
pub const IORING_OP_RECVMSG:      u8 = 10;
pub const IORING_OP_TIMEOUT:      u8 = 11;
pub const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
pub const IORING_OP_ACCEPT:       u8 = 13;
pub const IORING_OP_ASYNC_CANCEL: u8 = 14;
pub const IORING_OP_LINK_TIMEOUT: u8 = 15;
pub const IORING_OP_CONNECT:      u8 = 16;
pub const IORING_OP_FALLOCATE:    u8 = 17;
pub const IORING_OP_OPENAT:       u8 = 18;
pub const IORING_OP_CLOSE:        u8 = 19;
pub const IORING_OP_FILES_UPDATE: u8 = 20;
pub const IORING_OP_STATX:        u8 = 21;
pub const IORING_OP_READ:         u8 = 22;
pub const IORING_OP_WRITE:        u8 = 23;
pub const IORING_OP_FADVISE:      u8 = 24;
pub const IORING_OP_MADVISE:      u8 = 25;
pub const IORING_OP_SEND:         u8 = 26;
pub const IORING_OP_RECV:         u8 = 27;

/// One past the highest opcode oxide knows. Reported as `io_uring_probe`'s
/// `last_op` (Linux reports `IORING_OP_LAST - 1`), and the clamp
/// `io_probe()` applies to `nr_args`.
pub const OP_COUNT: u32 = IORING_OP_RECV as u32 + 1;

/// `IOSQE_FIXED_FILE` — SQE `fd` is an index into the registered-files array.
pub const IOSQE_FIXED_FILE:       u8 = 1 << 0;
/// `IOSQE_IO_DRAIN`.
pub const IOSQE_IO_DRAIN:         u8 = 1 << 1;
/// `IOSQE_IO_LINK`.
pub const IOSQE_IO_LINK:          u8 = 1 << 2;
/// `IOSQE_IO_HARDLINK`.
pub const IOSQE_IO_HARDLINK:      u8 = 1 << 3;
/// `IOSQE_ASYNC`.
pub const IOSQE_ASYNC:            u8 = 1 << 4;
/// `IOSQE_BUFFER_SELECT`.
pub const IOSQE_BUFFER_SELECT:    u8 = 1 << 5;
/// `IOSQE_CQE_SKIP_SUCCESS`.
pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

/// `IORING_FSYNC_DATASYNC` — `IORING_OP_FSYNC`'s `fsync_flags` bit selecting
/// `fdatasync` semantics.
pub const IORING_FSYNC_DATASYNC: u32 = 1 << 0;

/// SQE flags oxide honours. `IOSQE_ASYNC` is a scheduling hint only (every op
/// already runs to completion inline), so honouring it is a no-op; the
/// ordering flags are not, and an SQE that carries one is refused rather than
/// silently executed out of order (Linux `io_init_req`: an unsupported SQE
/// flag is `-EINVAL`).
pub const SUPPORTED_SQE_FLAGS: u8 = IOSQE_FIXED_FILE | IOSQE_ASYNC;

/// Whether `dispatch_op` actually executes this opcode. # C: O(1)
pub fn op_supported(op: u8) -> bool {
    matches!(op,
        IORING_OP_NOP | IORING_OP_READV | IORING_OP_WRITEV | IORING_OP_FSYNC
        | IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED | IORING_OP_ACCEPT
        | IORING_OP_CONNECT | IORING_OP_OPENAT | IORING_OP_CLOSE
        | IORING_OP_READ | IORING_OP_WRITE | IORING_OP_SEND | IORING_OP_RECV)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_never_claims_an_opcode_dispatch_would_reject() {
        // These are real Linux opcodes oxide does not run. Reporting
        // IO_URING_OP_SUPPORTED for one makes liburing submit an SQE that
        // comes back -EINVAL.
        for op in [IORING_OP_POLL_ADD, IORING_OP_POLL_REMOVE, IORING_OP_SENDMSG,
                   IORING_OP_RECVMSG, IORING_OP_TIMEOUT, IORING_OP_ASYNC_CANCEL,
                   IORING_OP_LINK_TIMEOUT, IORING_OP_FALLOCATE, IORING_OP_STATX,
                   IORING_OP_FILES_UPDATE, IORING_OP_FADVISE, IORING_OP_MADVISE,
                   IORING_OP_SYNC_FILE_RANGE, IORING_OP_TIMEOUT_REMOVE] {
            assert!(!op_supported(op), "op {op}");
        }
    }

    #[test]
    fn probe_claims_every_dispatched_opcode() {
        for op in [IORING_OP_NOP, IORING_OP_READV, IORING_OP_WRITEV, IORING_OP_FSYNC,
                   IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED, IORING_OP_ACCEPT,
                   IORING_OP_CONNECT, IORING_OP_OPENAT, IORING_OP_CLOSE,
                   IORING_OP_READ, IORING_OP_WRITE, IORING_OP_SEND, IORING_OP_RECV] {
            assert!(op_supported(op), "op {op}");
        }
    }

    #[test]
    fn op_count_is_one_past_the_highest_known_opcode() {
        assert_eq!(OP_COUNT, 28);
        assert!(!op_supported(OP_COUNT as u8));
    }

    #[test]
    fn ordering_sqe_flags_are_not_in_the_supported_set() {
        // Accepting IO_LINK / IO_DRAIN silently would run linked SQEs
        // independently and in the wrong order.
        for f in [IOSQE_IO_DRAIN, IOSQE_IO_LINK, IOSQE_IO_HARDLINK,
                  IOSQE_BUFFER_SELECT, IOSQE_CQE_SKIP_SUCCESS] {
            assert_eq!(SUPPORTED_SQE_FLAGS & f, 0, "flag {f:#x}");
        }
        assert_ne!(SUPPORTED_SQE_FLAGS & IOSQE_FIXED_FILE, 0);
    }
}
