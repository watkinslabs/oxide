// Receive-side IPv4 option area: what a delivered header owes, and what a
// reply to it carries. Every case here is a byte-level contract — if the fill
// pass or the echo pass stops running, one of these fails.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::addr::Ipv4Addr;
use super::area::{Compiled, NoUnicast};
use super::rx;
use super::uapi::*;

/// The address this host answered every case on.
fn spec() -> Ipv4Addr { Ipv4Addr::new(192, 0, 2, 1) }
/// The sender every case replies to.
fn peer() -> Ipv4Addr { Ipv4Addr::new(198, 51, 100, 9) }
/// An arrival stamp distinct from every other byte in these areas.
const STAMP: u32 = 0x0102_0304;

/// The receive pass with no routing table to consult: a prespecified
/// timestamp slot names no address this host owns.
fn received(area: &[u8]) -> Result<Compiled, Errno> {
    rx::received(area, &NoUnicast, spec(), STAMP)
}

// ---- what a delivered header owes ---------------------------------------

#[test]
fn a_record_route_slot_takes_the_address_the_host_answered_on() {
    // Two empty slots, pointer at the first.
    let c = received(&[IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, IPOPT_END]).unwrap();
    assert_eq!(&c.data[3..7], &spec().octets());
    // The pointer names the next unused slot, one further along.
    assert_eq!(c.data[2], 8);
    assert!(c.rr_needaddr);
    // The second slot is still the sender's to give away.
    assert_eq!(&c.data[7..11], &[0, 0, 0, 0]);
}

#[test]
fn a_full_record_route_is_left_exactly_as_it_arrived() {
    let area = [IPOPT_RR, 7, 8, 10, 0, 0, 1, IPOPT_END];
    let c = received(&area).unwrap();
    assert_eq!(&c.data[..], &area);
    assert!(!c.rr_needaddr);
}

#[test]
fn a_timestamp_only_option_is_stamped_with_the_arrival_time() {
    let c = received(&[IPOPT_TIMESTAMP, 12, 5, IPOPT_TS_TSONLY,
        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(&c.data[4..8], &STAMP.to_be_bytes());
    assert_eq!(c.data[2], 9);
    assert!(c.ts_needtime);
    assert!(!c.ts_needaddr);
}

#[test]
fn a_timestamp_and_address_option_records_both() {
    let c = received(&[IPOPT_TIMESTAMP, 12, 5, IPOPT_TS_TSANDADDR,
        0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(&c.data[4..8], &spec().octets());
    assert_eq!(&c.data[8..12], &STAMP.to_be_bytes());
    assert_eq!(c.data[2], 13);
    assert!(c.ts_needaddr);
    assert!(c.ts_needtime);
}

#[test]
fn a_prespecified_slot_naming_another_host_is_stamped() {
    // `NoUnicast` answers that no address belongs elsewhere, which is the
    // "this slot is ours to stamp" case.
    let c = received(&[IPOPT_TIMESTAMP, 12, 5, IPOPT_TS_PRESPEC,
        192, 0, 2, 1, 0, 0, 0, 0]).unwrap();
    assert_eq!(&c.data[8..12], &STAMP.to_be_bytes());
    assert_eq!(c.data[2], 13);
}

#[test]
fn a_timestamp_option_with_no_slot_left_advances_the_overflow_counter() {
    let c = received(&[IPOPT_TIMESTAMP, 8, 9, IPOPT_TS_TSONLY, 0, 0, 0, 0]).unwrap();
    assert_eq!(c.data[3] >> 4, 1);
    assert_eq!(c.data[3] & 0xf, IPOPT_TS_TSONLY);
    // The pointer does not move once there is nothing left to fill.
    assert_eq!(c.data[2], 9);
}

#[test]
fn an_overflow_counter_already_at_its_maximum_is_a_header_error() {
    let full = (15 << 4) | IPOPT_TS_TSONLY;
    assert_eq!(received(&[IPOPT_TIMESTAMP, 8, 9, full, 0, 0, 0, 0]), Err(Errno::Einval));
}

#[test]
fn a_received_area_that_does_not_parse_is_a_header_error() {
    // A length that overruns the area, and a length below the minimum.
    assert_eq!(received(&[IPOPT_RR, 40, 4, 0]), Err(Errno::Einval));
    assert_eq!(received(&[IPOPT_RR, 1, 0, 0]), Err(Errno::Einval));
    // An area whose length is not a four-byte multiple is not a header.
    assert_eq!(received(&[IPOPT_RR, 7, 4, 0, 0, 0, 0]), Err(Errno::Einval));
}

#[test]
fn a_received_source_route_keeps_its_first_hop_in_the_list() {
    // The socket-side pass lifts the first hop out and shifts the list down;
    // a received route is a routing question and is left untouched.
    let area = [IPOPT_LSRR, 11, 4, 10, 0, 0, 1, 10, 0, 0, 2, IPOPT_END];
    let c = received(&area).unwrap();
    assert_eq!(&c.data[..], &area);
    assert_eq!(c.faddr, [0, 0, 0, 0]);
    assert!(!c.is_strictroute);
}

#[test]
fn an_option_kind_no_socket_may_construct_is_still_delivered() {
    // A security option cannot be set on a socket without `CAP_NET_RAW`, but a
    // packet carrying one was not constructed here and is not refused.
    assert!(received(&[IPOPT_SEC, 4, 0, 0]).is_ok());
    assert!(received(&[IPOPT_SID, 4, 0, 0]).is_ok());
}

// ---- what a reply carries -----------------------------------------------

/// The echoed reply to an area as it arrived here.
fn echo_of(area: &[u8]) -> Compiled {
    rx::echo(&received(area).unwrap(), peer()).unwrap()
}

#[test]
fn the_reply_steps_the_record_route_pointer_over_the_slot_it_will_fill() {
    let d = echo_of(&[IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, IPOPT_END]);
    // This host's address rode back, and the pointer names the slot the reply
    // will record its own address in on the way out.
    assert_eq!(&d.data[3..7], &spec().octets());
    assert_eq!(d.data[2], 12);
    assert!(d.rr_needaddr);
}

#[test]
fn the_received_area_publication_retracts_only_what_the_echo_advanced() {
    let area = [IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, IPOPT_END];
    let filled = received(&area).unwrap();
    let d = rx::echo(&filled, peer()).unwrap();
    // What IP_RECVOPTS publishes is the area as this host recorded it — the
    // echo's own pointer advance undone, this host's own record kept.
    assert_eq!(&super::undo(&d)[..11], &filled.data[..11]);
}

#[test]
fn the_reply_keeps_the_record_route_and_timestamp_and_drops_the_rest() {
    // A record route, a security option, then a timestamp: the reply carries
    // the first and the last, never the security option.
    let area = [IPOPT_RR, 7, 4, 0, 0, 0, 0,
        IPOPT_SEC, 4, 0, 0,
        IPOPT_TIMESTAMP, 8, 5, IPOPT_TS_TSONLY, 0, 0, 0, 0,
        IPOPT_END];
    let d = echo_of(&area);
    assert_eq!(d.data[0], IPOPT_RR);
    assert_eq!(d.data[7], IPOPT_TIMESTAMP);
    assert!(!d.data.contains(&IPOPT_SEC));
    assert_eq!(d.data.len(), 16);
}

#[test]
fn the_reply_reverses_a_source_route() {
    // Three slots, all traversed: the pointer names the byte past the list.
    // The hop that forwarded the packet here leads the reply separately,
    // and the sender's own recorded slot is not named again.
    let area = [IPOPT_LSRR, 15, 16,
        198, 51, 100, 9,
        10, 0, 0, 2,
        10, 0, 0, 3,
        IPOPT_END];
    let d = echo_of(&area);
    assert_eq!(d.faddr, [10, 0, 0, 3]);
    assert_eq!(d.data[0], IPOPT_LSRR);
    assert_eq!(d.data[2], 4);
    assert_eq!(d.data[1] as usize, 7);
    assert_eq!(&d.data[3..7], &[10, 0, 0, 2]);
    assert!(d.srr.is_some());
}

#[test]
fn a_reply_route_whose_lowest_slot_is_another_host_keeps_it() {
    let area = [IPOPT_LSRR, 15, 16,
        10, 0, 0, 1,
        10, 0, 0, 2,
        10, 0, 0, 3,
        IPOPT_END];
    let d = echo_of(&area);
    assert_eq!(d.data[1] as usize, 11);
    assert_eq!(&d.data[3..7], &[10, 0, 0, 2]);
    assert_eq!(&d.data[7..11], &[10, 0, 0, 1]);
}

#[test]
fn a_strict_source_route_replies_strictly() {
    let area = [IPOPT_SSRR, 15, 16,
        10, 0, 0, 1,
        10, 0, 0, 2,
        10, 0, 0, 3,
        IPOPT_END];
    let d = echo_of(&area);
    assert_eq!(d.data[0], IPOPT_SSRR);
    assert!(d.is_strictroute);
}

#[test]
fn a_source_route_with_one_traversed_hop_echoes_nothing() {
    // The only visited hop becomes the reply's first hop, which travels
    // outside the option, so no list remains to publish.
    let d = echo_of(&[IPOPT_LSRR, 7, 8, 10, 0, 0, 1, IPOPT_END]);
    assert!(d.is_empty());
}

#[test]
fn a_reply_area_is_padded_to_a_four_byte_multiple() {
    let d = echo_of(&[IPOPT_RR, 7, 4, 0, 0, 0, 0, IPOPT_END]);
    assert_eq!(d.data.len() % 4, 0);
}

#[test]
fn a_header_with_no_option_area_replies_with_nothing() {
    assert!(received(&[]).unwrap().is_empty());
    assert!(rx::echo(&Compiled::default(), peer()).unwrap().is_empty());
}

#[test]
fn a_commercial_security_option_rides_the_reply_verbatim() {
    let area = [IPOPT_CIPSO, 8, 0, 0, 0, 1, 2, 2, IPOPT_END, IPOPT_END, IPOPT_END, IPOPT_END];
    let c = received(&area).unwrap();
    let d = rx::echo(&c, peer()).unwrap();
    assert_eq!(&d.data[..8], &area[..8]);
    assert_eq!(d.cipso, Some(0));
}

#[test]
fn every_reply_area_is_a_header_a_transmit_path_can_carry() {
    for area in [
        Vec::from([IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, IPOPT_END]),
        Vec::from([IPOPT_TIMESTAMP, 12, 5, IPOPT_TS_TSANDADDR, 0, 0, 0, 0, 0, 0, 0, 0]),
    ] {
        let d = echo_of(&area);
        assert_eq!(d.data.len() % 4, 0);
        assert!(d.data.len() <= MAX_IPOPTLEN);
    }
}
