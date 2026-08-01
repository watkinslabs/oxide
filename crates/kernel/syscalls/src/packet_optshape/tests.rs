// The AF_PACKET write shape rules, asserted on returned values.

use super::*;
use net::uapi::{PACKET_COPY_THRESH, PACKET_LOSS, PACKET_QDISC_BYPASS, PACKET_RESERVE,
    PACKET_TIMESTAMP, PACKET_TX_HAS_OFF, PACKET_VNET_HDR, PACKET_VNET_HDR_SZ,
    VIRTIO_NET_HDR_LEN};

#[test]
fn the_offload_options_carry_their_linux_numbers() {
    // A wrong number silently answers a different option, so pin them here
    // rather than trusting the dispatch arm to name the right constant.
    assert_eq!((PACKET_COPY_THRESH, PACKET_TIMESTAMP, PACKET_TX_HAS_OFF), (7, 17, 19));
    assert_eq!((PACKET_QDISC_BYPASS, PACKET_LOSS, PACKET_RESERVE), (20, 14, 12));
    assert_eq!((PACKET_VNET_HDR, PACKET_VNET_HDR_SZ), (15, 24));
}

#[test]
fn scalar_options_demand_their_exact_width() {
    for optname in [PACKET_COPY_THRESH, PACKET_TIMESTAMP, PACKET_LOSS,
        PACKET_QDISC_BYPASS, PACKET_TX_HAS_OFF, PACKET_RESERVE]
    {
        assert_eq!(check_set_len(optname, 4), Ok(4), "{optname}");
        // Short AND long are both refused — a scalar option is not a prefix.
        assert_eq!(check_set_len(optname, 3), Err(Errno::Einval), "{optname}");
        assert_eq!(check_set_len(optname, 8), Err(Errno::Einval), "{optname}");
        assert_eq!(check_set_len(optname, 0), Err(Errno::Einval), "{optname}");
    }
}

#[test]
fn the_vnet_header_pair_takes_a_leading_int_and_ignores_the_tail() {
    for optname in [PACKET_VNET_HDR, PACKET_VNET_HDR_SZ] {
        assert_eq!(check_set_len(optname, 4), Ok(4), "{optname}");
        assert_eq!(check_set_len(optname, 64), Ok(4),
            "a wider write still imports exactly the leading int");
        assert_eq!(check_set_len(optname, 3), Err(Errno::Einval), "{optname}");
    }
}

#[test]
fn an_unknown_packet_option_is_enoprotoopt_not_einval() {
    // The distinction matters: EINVAL says "your argument was wrong", which a
    // caller probing for feature support would read as "the option exists".
    assert_eq!(check_set_len(0xdead, 4), Err(Errno::Enoprotoopt));
    assert_eq!(set_len(0xdead), None);
    // The obsolete numbers Linux itself never implemented stay unknown.
    for obsolete in [net::uapi::PACKET_RECV_OUTPUT, net::uapi::PACKET_TX_TIMESTAMP] {
        assert_eq!(set_len(obsolete), None, "{obsolete}");
        assert_eq!(check_set_len(obsolete, 4), Err(Errno::Enoprotoopt), "{obsolete}");
    }
}

#[test]
fn vnet_header_refuses_a_cooked_socket_before_it_looks_at_the_buffer() {
    // A cooked socket is EINVAL whatever the length, so the refusal cannot be
    // reached by any argument shape — and never becomes EFAULT.
    for optlen in [0, 3, 4, 64] {
        assert_eq!(vnet_hdr_admit(false, optlen), Err(Errno::Einval), "optlen {optlen}");
    }
    assert_eq!(vnet_hdr_admit(true, 3), Err(Errno::Einval), "a short write is still refused");
    assert_eq!(vnet_hdr_admit(true, 4), Ok(4));
}

#[test]
fn vnet_hdr_is_a_boolean_and_vnet_hdr_sz_is_a_size() {
    // Any non-zero request selects the standard header length, NOT the
    // caller's number — the two options are not interchangeable.
    assert_eq!(vnet_hdr_size(0, false), 0);
    assert_eq!(vnet_hdr_size(1, false), VIRTIO_NET_HDR_LEN);
    assert_eq!(vnet_hdr_size(9999, false), VIRTIO_NET_HDR_LEN);
    assert_eq!(vnet_hdr_size(u32::MAX, false), VIRTIO_NET_HDR_LEN);
    // The explicit-size twin passes the number through untouched.
    assert_eq!(vnet_hdr_size(0, true), 0);
    assert_eq!(vnet_hdr_size(1, true), 1);
    assert_eq!(vnet_hdr_size(9999, true), 9999);
    assert_ne!(vnet_hdr_size(1, true), vnet_hdr_size(1, false));
}

#[test]
fn the_vnet_header_pair_round_trips_through_its_own_rule() {
    // What a caller writes through one option is what the SAME option reads
    // back — and the twin reads back something different, by design.
    for request in [0u32, 1, 42, 9999] {
        let stored = vnet_hdr_size(request, false);
        assert_eq!(vnet_hdr_get(stored, false), i32::from(request != 0),
            "PACKET_VNET_HDR is a boolean end to end");
        let sized = vnet_hdr_size(request, true);
        assert_eq!(vnet_hdr_get(sized, true), request as i32,
            "PACKET_VNET_HDR_SZ round-trips the size verbatim");
    }
    // The cross readings are the bug this rule exists to prevent: a socket
    // carrying the standard header reports `1` through the boolean option and
    // the header length through the size option.
    let standard = vnet_hdr_size(1, false);
    assert_eq!(vnet_hdr_get(standard, false), 1);
    assert_eq!(vnet_hdr_get(standard, true), VIRTIO_NET_HDR_LEN as i32);
    assert_ne!(vnet_hdr_get(standard, false), vnet_hdr_get(standard, true));
}
