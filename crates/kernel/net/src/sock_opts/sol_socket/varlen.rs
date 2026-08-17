// SOL_SOCKET reads whose value is not one fixed-width scalar: the memory
// report, the peer group list, the peer address, and the attached classic
// filter. Each has its own length ladder, so they never reach the scalar table.
//
// No target gate: the decision logic must run under hosted `cargo test`.

use syscall::errno::Errno;
use super::{SK_MEMINFO_VARS, SO_ATTACH_FILTER, SO_GET_FILTER};
use crate::socket_args::{AF_INET, AF_INET6, AF_UNIX, IPPROTO_IP, IPPROTO_MPTCP, IPPROTO_SCTP,
                         IPPROTO_TCP, SOCK_SEQPACKET, SOCK_STREAM};

/// `sk_get_meminfo` slots, in wire order. # C: O(1)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct MemInfo {
    pub rmem_alloc: u32,
    pub rcvbuf: u32,
    pub wmem_alloc: u32,
    pub sndbuf: u32,
    pub fwd_alloc: u32,
    pub wmem_queued: u32,
    pub optmem: u32,
    pub backlog: u32,
    pub drops: u32,
}

impl MemInfo {
    /// # C: O(1)
    pub fn words(&self) -> [u32; SK_MEMINFO_VARS] {
        [self.rmem_alloc, self.rcvbuf, self.wmem_alloc, self.sndbuf, self.fwd_alloc,
         self.wmem_queued, self.optmem, self.backlog, self.drops]
    }

    /// Native encoding of the whole report. # C: O(1)
    pub fn bytes(&self) -> [u8; SK_MEMINFO_VARS * core::mem::size_of::<u32>()] {
        let mut out = [0u8; SK_MEMINFO_VARS * core::mem::size_of::<u32>()];
        for (slot, word) in self.words().iter().enumerate() {
            let at = slot * core::mem::size_of::<u32>();
            out[at..at + core::mem::size_of::<u32>()].copy_from_slice(&word.to_ne_bytes());
        }
        out
    }
}

/// `SO_MEMINFO` truncates to the caller's buffer and never fails on a short
/// one; the published length is what was actually written. # C: O(1)
pub fn meminfo_len(requested: i32) -> usize {
    core::cmp::min(requested as usize, SK_MEMINFO_VARS * core::mem::size_of::<u32>())
}

/// `SO_PEERGROUPS`: no peer credential is `ENODATA`, and a buffer too small for
/// the whole list is `ERANGE` **after** the needed length is published — the
/// caller retries with the length it was told. # C: O(1)
pub fn peergroups_len(groups: Option<usize>, requested: i32) -> Result<usize, (usize, Errno)> {
    let Some(count) = groups else { return Err((0, Errno::Enodata)); };
    let needed = count * core::mem::size_of::<u32>();
    if (requested as usize) < needed { return Err((needed, Errno::Erange)); }
    Ok(needed)
}

/// `SO_PEERNAME`: an unconnected socket is `ENOTCONN`, and asking for more than
/// the peer address occupies is `EINVAL` — the option never zero-pads. The
/// caller receives exactly the length it asked for. # C: O(1)
pub fn peername_len(address_len: Option<usize>, requested: i32) -> Result<usize, Errno> {
    let Some(address_len) = address_len else { return Err(Errno::Enotconn); };
    if address_len < requested as usize { return Err(Errno::Einval); }
    Ok(requested as usize)
}

/// Whether a socket of this shape reports a peer security label at all.
/// # C: O(1)
///
/// Only the connection-oriented socket classes carry one: a peer label is a
/// property of an established connection, so a class that has no peer has
/// nowhere to have recorded it. Every other class leaves the peer label
/// unspecified, and an unspecified peer label is `ENOPROTOOPT` — which is also
/// the answer a caller gets when no module labels sockets at all.
///
/// `SOCK_SEQPACKET` counts as connection-oriented on both sides of the family
/// split. On AF_UNIX it shares the stream class outright; on AF_INET it is
/// classed with stream and then admitted or refused by its protocol, exactly
/// as `SOCK_STREAM` is.
pub fn reports_peer_label(family: u32, socket_type: u32, protocol: u32) -> bool {
    match family {
        AF_UNIX => matches!(socket_type, SOCK_STREAM | SOCK_SEQPACKET),
        AF_INET | AF_INET6 => matches!(socket_type, SOCK_STREAM | SOCK_SEQPACKET)
            && matches!(protocol, IPPROTO_IP | IPPROTO_TCP | IPPROTO_MPTCP | IPPROTO_SCTP),
        _ => false,
    }
}

/// `SO_PEERSEC`: an unspecified peer label is `ENOPROTOOPT` with nothing
/// written at all, and a buffer too small for the context is `ERANGE` **after**
/// the needed length is published — the caller sizes with one call and reads
/// with the next. # C: O(1)
///
/// `label_len` counts the context's terminating NUL, because the value copied
/// out is a C string and the length published alongside it is the allocation a
/// caller needs to hold that string. Publishing `strlen` instead would have
/// every caller allocate one byte short and read past the end of its own
/// buffer on the retry.
///
/// A buffer of exactly the context's length is accepted: the refusal is for a
/// buffer SMALLER than the context, never one that fits it exactly.
pub fn peersec_len(label_len: Option<usize>, requested: i32) -> Result<usize, (usize, Errno)> {
    let Some(needed) = label_len else { return Err((0, Errno::Enoprotoopt)); };
    if needed > requested as usize { return Err((needed, Errno::Erange)); }
    Ok(needed)
}

/// One accepted `SO_GET_FILTER` read: the byte count to copy out, and the
/// published length — which counts filter BLOCKS, not bytes. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FilterRead { pub copy_bytes: usize, pub published_len: usize }

/// `sock_filter` is four fields packed into eight bytes.
pub const SOCK_FILTER_SIZE: usize = 8;

/// `sk_get_filter`: nothing attached publishes a zero length; a program with no
/// retained classic source cannot be dumped (`EACCES`); a zero-length request
/// is the block-count enquiry; and a request smaller than the block count is
/// `EINVAL`. `classic_bytes` is `None` when the attached program is not classic.
/// # C: O(1)
pub fn get_filter(classic_bytes: Option<usize>, attached: bool, requested: i32)
    -> Result<FilterRead, Errno>
{
    if !attached { return Ok(FilterRead { copy_bytes: 0, published_len: 0 }); }
    let Some(bytes) = classic_bytes else { return Err(Errno::Eacces); };
    let blocks = bytes / SOCK_FILTER_SIZE;
    if requested == 0 { return Ok(FilterRead { copy_bytes: 0, published_len: blocks }); }
    if (requested as usize) < blocks { return Err(Errno::Einval); }
    Ok(FilterRead { copy_bytes: blocks * SOCK_FILTER_SIZE, published_len: blocks })
}

/// The read direction of `SO_ATTACH_FILTER`'s number. # C: O(1)
pub fn is_get_filter(optname: u64) -> bool { optname == SO_GET_FILTER }

/// Both names denote one option number. # C: O(1)
pub fn get_filter_shares_attach_number() -> bool { SO_GET_FILTER == SO_ATTACH_FILTER }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_encodes_nine_native_words_in_wire_order() {
        let info = MemInfo { rmem_alloc: 1, rcvbuf: 2, wmem_alloc: 3, sndbuf: 4,
            fwd_alloc: 5, wmem_queued: 6, optmem: 7, backlog: 8, drops: 9 };
        assert_eq!(info.words(), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let bytes = info.bytes();
        assert_eq!(bytes.len(), 36);
        assert_eq!(u32::from_ne_bytes(bytes[32..].try_into().unwrap()), 9);
    }

    #[test]
    fn meminfo_truncates_a_short_request_instead_of_failing() {
        assert_eq!(meminfo_len(4), 4);
        assert_eq!(meminfo_len(0), 0);
        assert_eq!(meminfo_len(36), 36);
        assert_eq!(meminfo_len(i32::MAX), 36);
    }

    #[test]
    fn peergroups_publishes_the_needed_length_before_erange() {
        assert_eq!(peergroups_len(None, 64), Err((0, Errno::Enodata)));
        assert_eq!(peergroups_len(Some(3), 8), Err((12, Errno::Erange)));
        assert_eq!(peergroups_len(Some(3), 12), Ok(12));
        assert_eq!(peergroups_len(Some(0), 0), Ok(0));
    }

    #[test]
    fn peername_rejects_a_request_wider_than_the_address() {
        assert_eq!(peername_len(None, 16), Err(Errno::Enotconn));
        assert_eq!(peername_len(Some(16), 17), Err(Errno::Einval));
        assert_eq!(peername_len(Some(16), 16), Ok(16));
        assert_eq!(peername_len(Some(16), 4), Ok(4));
    }

    /// The sizing call and the reading call a labelled peer's consumer makes:
    /// it asks with a fixed buffer, and on `ERANGE` re-asks with exactly the
    /// length it was handed. The second call must then succeed, so the length
    /// published by the first has to be the length the second accepts.
    #[test]
    fn peersec_publishes_the_needed_length_before_erange_and_accepts_it_back() {
        // "unlabeled" plus its terminating NUL.
        let context = 10usize;
        assert_eq!(peersec_len(Some(context), 4), Err((context, Errno::Erange)));
        // The caller retries with precisely what it was told, and is accepted.
        assert_eq!(peersec_len(Some(context), context as i32), Ok(context));
        // A buffer wider than the context copies only the context.
        assert_eq!(peersec_len(Some(context), 256), Ok(context));
        // One byte short is still short.
        assert_eq!(peersec_len(Some(context), context as i32 - 1),
            Err((context, Errno::Erange)));
    }

    /// An unspecified peer label publishes NOTHING — not a zero length. A zero
    /// published length would tell a caller the peer's context is the empty
    /// string, and it would then hand that empty string on as a label.
    #[test]
    fn peersec_without_a_label_publishes_no_length_at_all() {
        assert_eq!(peersec_len(None, 256), Err((0, Errno::Enoprotoopt)));
        assert_eq!(peersec_len(None, 0), Err((0, Errno::Enoprotoopt)));
    }

    /// A zero-length request is the sizing enquiry, and it is still `ERANGE`:
    /// `SO_PEERSEC` has no "tell me the length without failing" form, unlike
    /// `SO_GET_FILTER`.
    #[test]
    fn peersec_answers_a_zero_length_enquiry_with_erange_and_the_length() {
        assert_eq!(peersec_len(Some(10), 0), Err((10, Errno::Erange)));
    }

    #[test]
    fn only_connection_oriented_socket_classes_report_a_peer_label() {
        use crate::socket_args::{AF_NETLINK, AF_PACKET, IPPROTO_ICMP, IPPROTO_UDP, SOCK_DGRAM,
                                 SOCK_RAW};
        // The AF_UNIX stream class — the one a session bus reads.
        assert!(reports_peer_label(AF_UNIX, SOCK_STREAM, 0));
        assert!(reports_peer_label(AF_UNIX, SOCK_SEQPACKET, 0));
        // An AF_UNIX datagram socket records a peer label at socketpair time
        // and STILL reports none: the class, not the recording, decides.
        assert!(!reports_peer_label(AF_UNIX, SOCK_DGRAM, 0));
        assert!(!reports_peer_label(AF_UNIX, SOCK_RAW, 0));
        // The connection-oriented INET classes.
        for family in [AF_INET, AF_INET6] {
            assert!(reports_peer_label(family, SOCK_STREAM, IPPROTO_IP));
            assert!(reports_peer_label(family, SOCK_STREAM, IPPROTO_TCP));
            assert!(reports_peer_label(family, SOCK_STREAM, IPPROTO_MPTCP));
            assert!(reports_peer_label(family, SOCK_STREAM, IPPROTO_SCTP));
            // A stream socket on any other protocol is a raw-IP socket.
            assert!(!reports_peer_label(family, SOCK_STREAM, IPPROTO_ICMP));
            assert!(!reports_peer_label(family, SOCK_DGRAM, IPPROTO_UDP));
            assert!(!reports_peer_label(family, SOCK_RAW, IPPROTO_TCP));
        }
        assert!(!reports_peer_label(AF_PACKET, SOCK_RAW, 0));
        assert!(!reports_peer_label(AF_NETLINK, SOCK_DGRAM, 0));
    }

    #[test]
    fn get_filter_publishes_block_counts_not_byte_counts() {
        assert_eq!(get_filter(None, false, 64), Ok(FilterRead { copy_bytes: 0, published_len: 0 }));
        assert_eq!(get_filter(None, true, 64), Err(Errno::Eacces));
        assert_eq!(get_filter(Some(24), true, 0),
            Ok(FilterRead { copy_bytes: 0, published_len: 3 }));
        assert_eq!(get_filter(Some(24), true, 2), Err(Errno::Einval));
        assert_eq!(get_filter(Some(24), true, 3),
            Ok(FilterRead { copy_bytes: 24, published_len: 3 }));
        assert_eq!(get_filter(Some(24), true, 4096),
            Ok(FilterRead { copy_bytes: 24, published_len: 3 }));
    }

    #[test]
    fn get_filter_reuses_the_attach_option_number() {
        assert!(get_filter_shares_attach_number());
        assert!(is_get_filter(SO_ATTACH_FILTER));
    }
}
