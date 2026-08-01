// What a fast-open option means: the cookie length rules and the four
// classifications a received option gets.

use super::*;
use crate::tcp_conn::syn_opts::SynOptions;
use crate::tcp_hdr::{TcpHdr, TCP_HDR_MIN_LEN, flags};

const EIGHT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

// ---- the cookie value -----------------------------------------------------

#[test]
fn a_cookie_holds_the_bytes_it_was_built_from() {
    let c = Cookie::new(&EIGHT, false).unwrap();
    assert_eq!(c.as_bytes(), &EIGHT);
    assert_eq!(c.len(), 8);
    assert!(!c.is_request());
    assert!(!c.exp);
}

#[test]
fn the_shortest_and_longest_cookies_are_both_accepted() {
    assert!(Cookie::new(&[1, 2, 3, 4], false).is_some());
    assert!(Cookie::new(&[0u8; COOKIE_MAX], false).is_some());
    assert_eq!(Cookie::new(&[0u8; COOKIE_MAX], false).unwrap().len(), 16);
}

#[test]
fn a_cookie_outside_the_length_range_is_not_a_cookie() {
    assert!(Cookie::new(&[], false).is_none());
    assert!(Cookie::new(&[1, 2], false).is_none(), "shorter than the minimum");
    assert!(Cookie::new(&[0u8; 18], false).is_none(), "longer than the maximum");
    assert!(Cookie::new(&[1, 2, 3, 4, 5], false).is_none(), "odd lengths cannot appear");
}

#[test]
fn a_request_is_a_present_option_carrying_nothing() {
    let r = Cookie::request(false);
    assert!(r.is_request());
    assert!(r.is_empty());
    assert_eq!(r.as_bytes(), &[] as &[u8]);
}

#[test]
fn the_experimental_kind_is_carried_on_the_cookie() {
    assert!(Cookie::new(&EIGHT, true).unwrap().exp);
    assert!(Cookie::request(true).exp);
}

// ---- classification -------------------------------------------------------

#[test]
fn an_empty_option_body_is_a_request() {
    assert_eq!(classify(&[], false, true), FastOpen::Request { exp: false });
    assert_eq!(classify(&[], true, true), FastOpen::Request { exp: true });
}

#[test]
fn a_body_in_range_is_a_cookie() {
    assert_eq!(classify(&EIGHT, false, true), FastOpen::Cookie(Cookie::new(&EIGHT, false).unwrap()));
}

#[test]
fn a_body_out_of_range_is_present_but_unusable() {
    // Distinct from absent: the peer meant something, it just cannot be a
    // cookie. Two bytes is the length the reference singles out as invalid
    // rather than short.
    assert_eq!(classify(&[1, 2], false, true), FastOpen::Invalid { exp: false });
    assert_eq!(classify(&[0u8; 18], true, true), FastOpen::Invalid { exp: true });
}

#[test]
fn an_odd_body_is_ignored_entirely() {
    // A well-formed option cannot produce one, so there is nothing to answer.
    assert_eq!(classify(&[1, 2, 3], false, true), FastOpen::Absent);
    assert_eq!(classify(&[1], false, true), FastOpen::Absent);
}

#[test]
fn the_option_means_nothing_outside_a_handshake_segment() {
    assert_eq!(classify(&EIGHT, false, false), FastOpen::Absent);
    assert_eq!(classify(&[], false, false), FastOpen::Absent);
}

// ---- round trip through a real segment ------------------------------------

/// A segment carrying `opts`, with the SYN flag set unless told otherwise.
fn segment(opts: SynOptions, syn: bool) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN + opts.encoded_len()];
    opts.encode(&mut buf[TCP_HDR_MIN_LEN..]);
    let mut h = TcpHdr {
        src_port: 1, dst_port: 2, seq: 0, ack: 0,
        data_offset: opts.data_offset(),
        flags: if syn { flags::SYN } else { flags::ACK },
        window: 0, checksum: 0, urg_ptr: 0,
    };
    h.build_into(crate::addr::Ipv4Addr::new(127, 0, 0, 1),
                 crate::addr::Ipv4Addr::new(127, 0, 0, 1), &mut buf);
    buf
}

#[test]
fn a_written_cookie_reparses_under_the_assigned_kind() {
    let c = Cookie::new(&EIGHT, false).unwrap();
    let seg = segment(SynOptions { mss: Some(1460), fastopen: Some(c), ..SynOptions::default() }, true);
    assert_eq!(parse(&seg, true), FastOpen::Cookie(c));
}

#[test]
fn a_written_cookie_reparses_under_the_experimental_kind() {
    let c = Cookie::new(&EIGHT, true).unwrap();
    let seg = segment(SynOptions { mss: Some(1460), fastopen: Some(c), ..SynOptions::default() }, true);
    // The kind the exchange started under survives the round trip, so a reply
    // can answer in the form the peer understands.
    assert_eq!(parse(&seg, true), FastOpen::Cookie(c));
}

#[test]
fn a_written_request_reparses_as_a_request() {
    for exp in [false, true] {
        let seg = segment(SynOptions { fastopen: Some(Cookie::request(exp)), ..SynOptions::default() }, true);
        assert_eq!(parse(&seg, true), FastOpen::Request { exp });
    }
}

#[test]
fn a_segment_carrying_no_option_reparses_as_absent() {
    let seg = segment(SynOptions { mss: Some(1460), ..SynOptions::default() }, true);
    assert_eq!(parse(&seg, true), FastOpen::Absent);
}

#[test]
fn the_option_survives_being_written_after_every_other_option() {
    // Fast open is written last, so this is the case where a mis-sized
    // predecessor would swallow it.
    let c = Cookie::new(&EIGHT, false).unwrap();
    let opts = SynOptions {
        mss: Some(1460), timestamp: Some((9, 10)), sack_perm: true,
        wscale: Some(7), fastopen: Some(c),
    };
    let seg = segment(opts, true);
    assert_eq!(parse(&seg, true), FastOpen::Cookie(c));
    // Every earlier option still parses out of the same area.
    assert_eq!(crate::tcp_hdr::parse_mss_option(&seg), Some(1460));
    assert_eq!(crate::tcp_hdr::parse_wscale_option(&seg), Some(7));
    assert_eq!(crate::tcp_hdr::parse_ts_option(&seg), Some((9, 10)));
    assert!(crate::tcp_hdr::parse_sack_permitted(&seg));
}
