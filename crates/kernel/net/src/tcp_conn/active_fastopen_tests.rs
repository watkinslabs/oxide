// The client mechanism: what an opening SYN carrying data looks like on the
// wire, what the retransmit queue holds behind it, and what the answer does
// to both.
//
// The ladder that chose to fast open is unit-tested in
// `tcp_fastopen/client_tests.rs`; what is asserted here is the mechanism it
// drives — and above all that every way the fast open can fail still leaves
// the connection open and the bytes owed to the peer.

use super::*;
use crate::addr::{IpAddr, Ipv4Addr};
use crate::tcp_conn::syn_opts::SynOptions;
use crate::tcp_conn::Endpoint;

const ISN: u32 = 0x1000_0000;
const PEER_ISN: u32 = 0x9000_0000;
const DATA: &[u8] = b"GET / HTTP/1.1\r\n";

fn local() -> Endpoint { Endpoint { ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)), port: 40_000 } }
fn remote() -> Endpoint { Endpoint { ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), port: 80 } }

fn client() -> TcpConn { TcpConn::new_client(local(), remote(), ISN) }

fn cookie() -> Cookie { Cookie::minted([4; 8], false) }

/// A SYN-ACK from the peer, acknowledging `ack` and carrying `option`.
fn synack(ack: u32, option: Option<Cookie>) -> Vec<u8> {
    let opts = SynOptions { mss: Some(1460), fastopen: option, ..SynOptions::default() };
    let opt_len = opts.encoded_len();
    let mut buf = alloc::vec![0u8; crate::tcp_hdr::TCP_HDR_MIN_LEN + opt_len];
    opts.encode(&mut buf[crate::tcp_hdr::TCP_HDR_MIN_LEN..]);
    let mut hdr = crate::tcp_hdr::TcpHdr {
        src_port: remote().port, dst_port: local().port,
        seq: PEER_ISN, ack, data_offset: opts.data_offset(),
        flags: flags::SYN | flags::ACK, window: 65_535, checksum: 0, urg_ptr: 0,
    };
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (remote().ip, local().ip)
        else { unreachable!("the fixture is IPv4") };
    hdr.build_into(src, dst, &mut buf);
    buf
}

fn deliver(c: &mut TcpConn, seg: &[u8]) -> Option<Vec<u8>> {
    c.input(remote().ip, local().ip, seg).expect("a well-formed SYN-ACK")
}

#[test]
fn a_fast_open_syn_carries_the_cookie_and_the_data() {
    let mut c = client();
    let (seg, carried) = c.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    assert_eq!(carried, DATA.len());
    let hdr = crate::tcp_hdr::parse_prevalidated(&seg).expect("a well-formed SYN");
    assert_eq!(&seg[hdr.payload_offset()..], DATA);
    assert_eq!(crate::tcp_conn::fastopen::parse(&seg, true),
        crate::tcp_conn::fastopen::FastOpen::Cookie(cookie()));
    assert_eq!(c.snd_nxt, ISN.wrapping_add(1 + DATA.len() as u32),
        "the SYN consumes one sequence number and the data consumes its own");
}

#[test]
fn the_syn_and_its_data_are_two_entries_on_the_retransmit_queue() {
    let mut c = client();
    c.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    assert_eq!(c.retx_q.len(), 2);
    assert_eq!(c.retx_q[0].seq, ISN);
    assert!(c.retx_q[0].payload.is_empty(), "the SYN is retransmitted bare");
    assert_eq!(c.retx_q[1].seq, ISN.wrapping_add(1));
    assert_eq!(c.retx_q[1].payload, DATA);
}

#[test]
fn an_open_with_no_cookie_and_no_data_is_an_ordinary_syn() {
    let mut c = client();
    let (seg, carried) = c.active_open_fastopen(None, b"").expect("the open");
    assert_eq!(carried, 0);
    assert_eq!(crate::tcp_conn::fastopen::parse(&seg, true),
        crate::tcp_conn::fastopen::FastOpen::Absent);
    assert_eq!(c.retx_q.len(), 1);
    assert!(!c.syn_data);
}

#[test]
fn a_cookie_request_rides_a_syn_that_carries_no_data() {
    let mut c = client();
    let (seg, carried) = c.active_open_fastopen(Some(Cookie::request(false)), DATA)
        .expect("the open");
    // The ladder never pairs a request with data; passing both would be a
    // caller error, and the mechanism still emits exactly what it was given.
    assert_eq!(carried, DATA.len());
    assert_eq!(crate::tcp_conn::fastopen::parse(&seg, true),
        crate::tcp_conn::fastopen::FastOpen::Request { exp: false });
}

#[test]
fn the_data_is_bounded_by_what_fits_beside_the_handshakes_own_options() {
    let mut c = client();
    c.own_mss = 100;
    let big = alloc::vec![0x41u8; 4096];
    let (seg, carried) = c.active_open_fastopen(Some(cookie()), &big).expect("the open");
    assert!(carried > 0 && carried < big.len());
    assert!(seg.len() <= 100 + crate::tcp_hdr::TCP_HDR_MIN_LEN,
        "a SYN larger than the path's segment would be fragmented or dropped");
    assert_eq!(c.retx_q[1].payload.len(), carried, "the bytes not carried are not owed twice");
}

#[test]
fn a_retransmitted_syn_goes_out_bare_and_alone() {
    let mut c = client();
    c.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    let out = c.retransmit_due(c.rto_ns + 1);
    assert_eq!(out.len(), 1, "nothing behind the SYN may go out before the handshake finishes");
    assert_eq!(crate::tcp_conn::fastopen::parse(&out[0], true),
        crate::tcp_conn::fastopen::FastOpen::Absent,
        "the option is what a middlebox on this path may have objected to");
    let hdr = crate::tcp_hdr::parse_prevalidated(&out[0]).expect("a well-formed SYN");
    assert_eq!(hdr.payload_offset(), out[0].len(), "and it carries no data either");
}

#[test]
fn a_peer_that_took_the_data_leaves_nothing_owed() {
    let mut c = client();
    c.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    deliver(&mut c, &synack(ISN.wrapping_add(1 + DATA.len() as u32), None));
    assert_eq!(c.state, crate::tcp_state::TcpState::Established);
    assert!(c.syn_data_acked);
    assert!(c.retx_q.is_empty(), "both the SYN and its data are acknowledged");
    assert_eq!(c.fastopen_learned.expect("the answer was read").failed, false);
}

#[test]
fn a_peer_that_took_only_the_syn_still_owes_the_data_and_it_goes_out_again() {
    let mut c = client();
    c.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    deliver(&mut c, &synack(ISN.wrapping_add(1), None));
    assert_eq!(c.state, crate::tcp_state::TcpState::Established,
        "the connection is open either way; only the shortcut failed");
    assert!(!c.syn_data_acked);
    assert!(c.fastopen_learned.expect("the answer was read").failed);
    assert_eq!(c.retx_q.len(), 1);
    assert_eq!(c.retx_q[0].payload, DATA);
    let out = c.retransmit_due(c.rto_ns + 1);
    assert_eq!(out.len(), 1);
    let hdr = crate::tcp_hdr::parse_prevalidated(&out[0]).expect("a well-formed segment");
    assert_eq!(&out[0][hdr.payload_offset()..], DATA,
        "the program's bytes reach the peer on the ordinary path");
}

#[test]
fn a_cookie_on_the_answer_is_learned_when_one_was_asked_for() {
    let mut c = client();
    c.active_open_fastopen(Some(Cookie::request(false)), b"").expect("the open");
    deliver(&mut c, &synack(ISN.wrapping_add(1), Some(cookie())));
    assert_eq!(c.fastopen_learned.expect("the answer was read").cookie, Some(cookie()));
}

#[test]
fn a_cookie_on_an_answer_nobody_asked_for_teaches_nothing() {
    let mut c = client();
    c.active_open_fastopen(None, b"").expect("the open");
    deliver(&mut c, &synack(ISN.wrapping_add(1), Some(cookie())));
    assert_eq!(c.fastopen_learned, None, "no fast open was attempted, so none was answered");
}

#[test]
fn an_answer_that_gave_no_cookie_asks_for_the_other_option_kind_next_time() {
    let mut c = client();
    c.active_open_fastopen(Some(Cookie::request(false)), b"").expect("the open");
    deliver(&mut c, &synack(ISN.wrapping_add(1), None));
    assert_eq!(c.fastopen_learned.expect("the answer was read").try_exp,
        crate::tcp_fastopen::TRY_EXP_EXPERIMENTAL);
}

#[test]
fn a_third_consecutive_timeout_on_a_fast_open_names_the_path_a_blackhole() {
    let mut c = client();
    c.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    assert!(!c.fastopen_blackholed(false));
    let mut now = 0u64;
    for _ in 0..2 {
        now += c.rto_ns + 1;
        c.retransmit_due(now);
    }
    assert!(c.fastopen_blackholed(false));
}

#[test]
fn an_ordinary_connection_that_times_out_is_no_evidence_about_fast_open() {
    let mut c = client();
    c.active_open_fastopen(None, b"").expect("the open");
    let mut now = 0u64;
    for _ in 0..4 {
        now += c.rto_ns + 1;
        c.retransmit_due(now);
    }
    assert!(!c.fastopen_blackholed(true));
}

#[test]
fn every_answer_to_a_fast_open_leaves_an_established_connection() {
    // The whole point: a peer may take the data, take only the SYN, answer
    // with a cookie, answer with none, or answer a SYN it never saw the
    // option on. None of those is a failed connection.
    for acked in [false, true] {
        for reply in [None, Some(cookie()), Some(Cookie::request(false))] {
            for option in [None, Some(cookie()), Some(Cookie::request(false))] {
                let mut c = client();
                let (_, carried) = c.active_open_fastopen(option, DATA).expect("the open");
                let ack = ISN.wrapping_add(1 + if acked { carried as u32 } else { 0 });
                deliver(&mut c, &synack(ack, reply));
                assert_eq!(c.state, crate::tcp_state::TcpState::Established);
                let owed: usize = c.retx_q.iter().map(|s| s.payload.len()).sum();
                assert_eq!(owed, if acked { 0 } else { DATA.len() },
                    "bytes the peer did not take are still owed, and none are owed twice");
            }
        }
    }
}

#[test]
fn a_client_that_had_no_cookie_to_present_says_so() {
    let mut c = client();
    c.active_open_fastopen(Some(Cookie::request(false)), b"").expect("the open");
    assert_eq!(c.fastopen_client_fail, crate::tcp_fastopen::TFO_COOKIE_UNAVAILABLE);
}

#[test]
fn a_client_whose_data_the_peer_did_not_take_says_which_way_it_failed() {
    let mut c = client();
    c.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    deliver(&mut c, &synack(ISN.wrapping_add(1), None));
    assert_eq!(c.fastopen_client_fail, crate::tcp_fastopen::TFO_DATA_NOT_ACKED);

    let mut retried = client();
    retried.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    retried.retransmit_due(retried.rto_ns + 1);
    deliver(&mut retried, &synack(ISN.wrapping_add(1), None));
    assert_eq!(retried.fastopen_client_fail, crate::tcp_fastopen::TFO_SYN_RETRANSMITTED);
}

#[test]
fn a_fast_open_that_worked_reports_no_reason_at_all() {
    let mut c = client();
    let (_, carried) = c.active_open_fastopen(Some(cookie()), DATA).expect("the open");
    deliver(&mut c, &synack(ISN.wrapping_add(1 + carried as u32), None));
    assert_eq!(c.fastopen_client_fail, crate::tcp_fastopen::TFO_STATUS_NONE);
}
