// The option area every handshake combination produces, byte for byte. The
// layout is what a peer parses, so it is pinned here rather than inferred from
// the writer.

use super::*;
use crate::tcp_conn::fastopen::{Cookie, COOKIE_MAX};

/// Encode into a full-sized area and return exactly the bytes written.
fn bytes(o: &SynOptions) -> alloc::vec::Vec<u8> {
    let mut buf = [0u8; MAX_OPTION_BYTES];
    let n = o.encode(&mut buf);
    assert_eq!(n, o.encoded_len(), "encode wrote a different length than it reported");
    buf[..n].to_vec()
}

fn full() -> SynOptions {
    SynOptions { mss: Some(1460), timestamp: Some((0x1122_3344, 0x5566_7788)),
                 sack_perm: true, wscale: Some(7), fastopen: None }
}

#[test]
fn an_empty_offer_occupies_no_option_area() {
    let o = SynOptions::default();
    assert_eq!(o.encoded_len(), 0);
    assert_eq!(bytes(&o), alloc::vec::Vec::<u8>::new());
    assert_eq!(o.data_offset(), 5);
}

#[test]
fn a_segment_size_offer_is_one_word() {
    let o = SynOptions { mss: Some(1460), ..SynOptions::default() };
    assert_eq!(bytes(&o), [opt::MSS, LEN_MSS, 0x05, 0xb4]);
    assert_eq!(o.data_offset(), 6);
}

#[test]
fn timestamps_are_padded_by_a_no_op_pair_when_they_stand_alone() {
    let o = SynOptions { timestamp: Some((1, 2)), ..SynOptions::default() };
    assert_eq!(bytes(&o), [
        opt::NOP, opt::NOP, opt::TIMESTAMP, LEN_TIMESTAMP,
        0, 0, 0, 1,
        0, 0, 0, 2,
    ]);
}

#[test]
fn selective_acknowledgement_shares_the_timestamp_padding() {
    let o = SynOptions { timestamp: Some((1, 2)), sack_perm: true, ..SynOptions::default() };
    // The no-op pair is spent on the option instead of being wasted, so the
    // pair costs nothing beyond the timestamp's own twelve bytes.
    assert_eq!(o.encoded_len(), 12);
    assert_eq!(bytes(&o), [
        opt::SACK_PERMIT, LEN_SACK_PERM, opt::TIMESTAMP, LEN_TIMESTAMP,
        0, 0, 0, 1,
        0, 0, 0, 2,
    ]);
}

#[test]
fn selective_acknowledgement_takes_its_own_word_without_timestamps() {
    let o = SynOptions { sack_perm: true, ..SynOptions::default() };
    assert_eq!(bytes(&o), [opt::NOP, opt::NOP, opt::SACK_PERMIT, LEN_SACK_PERM]);
}

#[test]
fn window_scale_is_padded_by_a_single_no_op() {
    let o = SynOptions { wscale: Some(7), ..SynOptions::default() };
    assert_eq!(bytes(&o), [opt::NOP, opt::WSCALE, LEN_WSCALE, 7]);
}

#[test]
fn a_zero_window_scale_is_still_an_offer() {
    // Scale zero means "I understand scaling and apply none", which is not the
    // same as omitting the option; omitting it disables scaling both ways.
    let offered = SynOptions { wscale: Some(0), ..SynOptions::default() };
    let absent = SynOptions { wscale: None, ..SynOptions::default() };
    assert_eq!(bytes(&offered), [opt::NOP, opt::WSCALE, LEN_WSCALE, 0]);
    assert_eq!(bytes(&absent), alloc::vec::Vec::<u8>::new());
    assert_ne!(offered.encoded_len(), absent.encoded_len());
}

#[test]
fn a_full_offer_packs_into_four_words() {
    let o = full();
    assert_eq!(o.encoded_len(), 20);
    assert_eq!(o.data_offset(), 10);
    assert_eq!(bytes(&o), [
        opt::MSS, LEN_MSS, 0x05, 0xb4,
        opt::SACK_PERMIT, LEN_SACK_PERM, opt::TIMESTAMP, LEN_TIMESTAMP,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        opt::NOP, opt::WSCALE, LEN_WSCALE, 7,
    ]);
}

#[test]
fn every_combination_lands_on_a_word_boundary_and_fits_the_header() {
    for mss in [None, Some(1460u16)] {
        for ts in [None, Some((1u32, 2u32))] {
            for sack in [false, true] {
                for ws in [None, Some(7u8)] {
                    let o = SynOptions { mss, timestamp: ts, sack_perm: sack, wscale: ws,
                                         fastopen: None };
                    let n = o.encoded_len();
                    assert_eq!(n % 4, 0, "{o:?} is not word aligned");
                    assert!(n <= MAX_OPTION_BYTES, "{o:?} overruns the option area");
                    assert_eq!(bytes(&o).len(), n);
                    assert_eq!(o.data_offset() as usize * 4, TCP_HDR_MIN_LEN + n);
                }
            }
        }
    }
}

// ---- fast open ------------------------------------------------------------

const EIGHT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn cookie(n: usize, exp: bool) -> Cookie {
    Cookie::new(&[0xa5u8; COOKIE_MAX][..n], exp).unwrap()
}

#[test]
fn a_cookie_request_is_one_word_under_the_assigned_kind() {
    let o = SynOptions { fastopen: Some(Cookie::request(false)), ..SynOptions::default() };
    // Kind and length come to two bytes, so the word is filled out with no-ops
    // rather than left for a peer to walk into.
    assert_eq!(bytes(&o), [opt::FASTOPEN, 2, opt::NOP, opt::NOP]);
}

#[test]
fn a_cookie_request_names_the_experiment_under_the_experimental_kind() {
    let o = SynOptions { fastopen: Some(Cookie::request(true)), ..SynOptions::default() };
    assert_eq!(bytes(&o), [opt::EXP, 4, 0xf9, 0x89]);
}

#[test]
fn an_eight_byte_cookie_is_padded_to_its_word_under_the_assigned_kind() {
    let o = SynOptions { fastopen: Some(Cookie::new(&EIGHT, false).unwrap()), ..SynOptions::default() };
    assert_eq!(o.encoded_len(), 12);
    assert_eq!(bytes(&o), [
        opt::FASTOPEN, 10, 1, 2,
        3, 4, 5, 6,
        7, 8, opt::NOP, opt::NOP,
    ]);
}

#[test]
fn an_eight_byte_cookie_fills_its_words_under_the_experimental_kind() {
    let o = SynOptions { fastopen: Some(Cookie::new(&EIGHT, true).unwrap()), ..SynOptions::default() };
    assert_eq!(o.encoded_len(), 12);
    assert_eq!(bytes(&o), [
        opt::EXP, 12, 0xf9, 0x89,
        1, 2, 3, 4,
        5, 6, 7, 8,
    ]);
}

#[test]
fn every_cookie_length_lands_on_a_word_boundary_under_both_kinds() {
    for exp in [false, true] {
        for n in [0usize, 4, 6, 8, 10, 12, 14, 16] {
            let c = if n == 0 { Cookie::request(exp) } else { cookie(n, exp) };
            let o = SynOptions { mss: Some(1460), fastopen: Some(c), ..SynOptions::default() };
            let len = o.encoded_len();
            assert_eq!(len % 4, 0, "cookie {n} exp {exp} is not word aligned");
            assert!(len <= MAX_OPTION_BYTES, "cookie {n} exp {exp} overruns the area");
            assert_eq!(bytes(&o).len(), len);
        }
    }
}

#[test]
fn a_full_offer_with_a_cookie_still_fits_the_option_area() {
    // The largest handshake this side can emit: every negotiated option plus
    // the longest cookie under the costlier kind.
    let o = SynOptions {
        mss: Some(1460), timestamp: Some((1, 2)), sack_perm: true, wscale: Some(7),
        fastopen: Some(cookie(COOKIE_MAX, true)),
    };
    assert_eq!(o.encoded_len(), 40);
    assert_eq!(o.encoded_len(), MAX_OPTION_BYTES, "the area is exactly full");
    assert_eq!(o.data_offset(), 15, "the largest data offset the field can hold");
    assert_eq!(bytes(&o).len(), 40);
}

#[test]
fn the_cookie_is_written_after_every_other_option() {
    let o = SynOptions {
        mss: Some(1460), timestamp: Some((1, 2)), sack_perm: true, wscale: Some(7),
        fastopen: Some(Cookie::new(&EIGHT, false).unwrap()),
    };
    let b = bytes(&o);
    assert_eq!(&b[..4], &[opt::MSS, LEN_MSS, 0x05, 0xb4]);
    assert_eq!(&b[16..20], &[opt::NOP, opt::WSCALE, LEN_WSCALE, 7]);
    assert_eq!(b[20], opt::FASTOPEN);
}

#[test]
fn a_buffer_too_small_is_left_untouched_rather_than_half_written() {
    // A partially written area would be parsed as a different set of options,
    // so nothing is written at all.
    let o = full();
    let mut buf = [0xffu8; 19];
    assert_eq!(o.encode(&mut buf), 0);
    assert!(buf.iter().all(|b| *b == 0xff));
}

#[test]
fn the_encoded_area_reparses_as_the_options_it_encoded() {
    // Drive the real parsers over a real header so the layout is verified by
    // what reads it, not by the writer's own arithmetic.
    let o = full();
    let mut seg = alloc::vec![0u8; TCP_HDR_MIN_LEN + o.encoded_len()];
    o.encode(&mut seg[TCP_HDR_MIN_LEN..]);
    seg[12] = o.data_offset() << 4;
    assert_eq!(crate::tcp_hdr::parse_mss_option(&seg), Some(1460));
    assert_eq!(crate::tcp_hdr::parse_wscale_option(&seg), Some(7));
    assert_eq!(crate::tcp_hdr::parse_ts_option(&seg), Some((0x1122_3344, 0x5566_7788)));
    assert!(crate::tcp_hdr::parse_sack_permitted(&seg));
}

#[test]
fn an_option_the_segment_does_not_carry_does_not_reparse() {
    let o = SynOptions { mss: Some(536), ..SynOptions::default() };
    let mut seg = alloc::vec![0u8; TCP_HDR_MIN_LEN + o.encoded_len()];
    o.encode(&mut seg[TCP_HDR_MIN_LEN..]);
    seg[12] = o.data_offset() << 4;
    assert_eq!(crate::tcp_hdr::parse_mss_option(&seg), Some(536));
    assert_eq!(crate::tcp_hdr::parse_wscale_option(&seg), None);
    assert_eq!(crate::tcp_hdr::parse_ts_option(&seg), None);
    assert!(!crate::tcp_hdr::parse_sack_permitted(&seg));
}
