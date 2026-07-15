/// Decoded Linux `io_uring_sqe` operands used by synchronous dispatch.
pub(crate) struct OpArgs {
    pub opcode:    u8,
    pub flags:     u8,
    pub fd:        i32,
    pub off:       u64,
    pub addr:      u64,
    pub len:       u32,
    pub op_flags:  u32,
    pub buf_index: u16,
}

impl OpArgs {
    /// Map `IORING_OP_ACCEPT`'s `addr`, `addr2`, and `accept_flags` unions to accept4. # C: O(1)
    pub(crate) fn accept_args(&self, fd: i32) -> syscall::SyscallArgs {
        syscall::SyscallArgs {
            a0: fd as u64,
            a1: self.addr,
            a2: self.off,
            a3: self.op_flags as u64,
            a4: 0,
            a5: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::socket_args::{parse_accept_flags, SOCK_CLOEXEC, SOCK_NONBLOCK};

    #[test]
    fn accept_uses_addr2_for_addrlen_and_accept_flags_for_descriptor_state() {
        let flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
        let op = OpArgs {
            opcode: 13, flags: 0, fd: 7, off: 0x2222, addr: 0x1111,
            len: 0, op_flags: flags, buf_index: 0,
        };
        let args = op.accept_args(9);
        assert_eq!((args.a0, args.a1, args.a2, args.a3), (9, 0x1111, 0x2222, flags as u64));
        let parsed = parse_accept_flags(args.a3).unwrap();
        assert!(parsed.cloexec);
        assert!(parsed.nonblock);
    }

    #[test]
    fn accept_does_not_take_flags_or_addrlen_from_len() {
        let op = OpArgs {
            opcode: 13, flags: 0xff, fd: 7, off: 0x3333, addr: 0x1111,
            len: u32::MAX, op_flags: 0, buf_index: 0,
        };
        let args = op.accept_args(7);
        assert_eq!(args.a2, 0x3333);
        assert_eq!(args.a3, 0);
        assert_eq!(parse_accept_flags(args.a3).unwrap().cloexec, false);
    }
}
