// The unread-bytes control message a receive publishes when the socket asked
// for one. Two option numbers turn it on — `SO_INQ` on an AF_UNIX stream and
// `TCP_INQ` on a TCP connection — and they differ only in the level and type
// the message is tagged with, so both build it here and there is exactly one
// place that decides its shape.

/// One unread-bytes report, ready to be pushed as a control message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InqCmsg {
    pub level: i32,
    pub ty: i32,
    /// Bytes a further receive would still find queued.
    pub bytes: i32,
}

impl InqCmsg {
    /// The report `SO_INQ` asks for: tagged at the socket level under the
    /// option's own number. # C: O(1)
    pub fn socket(bytes: i32) -> Self {
        Self { level: super::sol_socket::SOL_SOCKET as i32,
               ty: super::sol_socket::SCM_INQ, bytes }
    }

    /// The report `TCP_INQ` asks for: tagged at the transport level under the
    /// same number the option is set with. # C: O(1)
    pub fn tcp(bytes: i32) -> Self {
        Self { level: super::sol_tcp::SOL_TCP as i32,
               ty: super::sol_tcp::TCP_CM_INQ as i32, bytes }
    }

    /// The `int` payload the control message carries. # C: O(1)
    pub fn data(&self) -> [u8; 4] { self.bytes.to_ne_bytes() }
}

/// The count a TCP receive reports: what is still queued for the reader. A
/// connection that has seen its peer's FIN reports at least one byte even with
/// an empty queue, because that is what tells an application driven purely by
/// this number to call `recvmsg` once more and observe the end of stream.
/// # C: O(1)
pub fn tcp_inq(queued: usize, eof_seen: bool) -> i32 {
    let inq = queued.min(i32::MAX as usize) as i32;
    if inq == 0 && eof_seen { 1 } else { inq }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_option_numbers_tag_the_same_report_differently() {
        let unix = InqCmsg::socket(7);
        let tcp = InqCmsg::tcp(7);
        assert_eq!(unix.bytes, tcp.bytes);
        assert_ne!((unix.level, unix.ty), (tcp.level, tcp.ty));
        // Each is tagged with the level and number its own option lives at.
        assert_eq!((unix.level, unix.ty), (1, super::super::sol_socket::SCM_INQ));
        assert_eq!((tcp.level, tcp.ty), (6, super::super::sol_tcp::TCP_INQ as i32));
    }

    #[test]
    fn the_payload_is_a_native_int() {
        assert_eq!(InqCmsg::tcp(0x1234).data(), 0x1234i32.to_ne_bytes());
        assert_eq!(InqCmsg::tcp(-1).data(), (-1i32).to_ne_bytes());
    }

    #[test]
    fn a_queue_with_bytes_reports_exactly_what_is_queued() {
        assert_eq!(tcp_inq(0, false), 0);
        assert_eq!(tcp_inq(1, false), 1);
        assert_eq!(tcp_inq(4096, false), 4096);
        assert_eq!(tcp_inq(4096, true), 4096, "unread data outranks the end of stream");
    }

    #[test]
    fn an_empty_queue_at_end_of_stream_still_reports_a_byte() {
        // Reporting zero here would let a reader that trusts the count park
        // forever instead of taking the zero-length read that ends the stream.
        assert_eq!(tcp_inq(0, true), 1);
    }

    #[test]
    fn an_oversized_queue_saturates_rather_than_wrapping_negative() {
        assert_eq!(tcp_inq(usize::MAX, false), i32::MAX);
    }
}
