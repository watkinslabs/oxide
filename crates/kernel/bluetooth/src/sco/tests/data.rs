//! Data-path contract: what may be sent, what is delivered, and when the
//! reception status rides along.

use crate::sco::data::{self, RxPacket};
use crate::sco::link::CmdLog;
use crate::sco::sock::ScoSock;
use crate::uapi::bt::{BT_CONNECTED, BT_OPEN, BT_SCM_PKT_STATUS};
use crate::uapi::hci::HCI_MAX_SCO_SIZE;
use syscall::errno::Errno;

fn connected() -> ScoSock {
    let mut sk = ScoSock::new();
    sk.state = BT_CONNECTED;
    sk.mtu = 60;
    sk
}

#[test]
fn sending_needs_a_live_link() {
    let mut sk = connected();
    let mut tx = CmdLog::new();
    assert_eq!(data::send(&sk, 0x2a, b"voice", &mut tx), Ok(5));
    assert_eq!(tx.data[0], (0x2a, b"voice".to_vec()));
    sk.state = BT_OPEN;
    assert_eq!(data::send(&sk, 0x2a, b"voice", &mut tx), Err(Errno::Enotconn));
}

#[test]
fn a_packet_past_the_links_ceiling_is_refused_rather_than_split() {
    let sk = connected();
    let mut tx = CmdLog::new();
    let big = alloc::vec![0u8; 61];
    assert_eq!(data::send(&sk, 1, &big, &mut tx), Err(Errno::Einval));
    let huge = alloc::vec![0u8; HCI_MAX_SCO_SIZE + 1];
    assert_eq!(data::send(&sk, 1, &huge, &mut tx), Err(Errno::Einval));
    assert!(tx.data.is_empty());
    let exact = alloc::vec![0u8; 60];
    assert_eq!(data::send(&sk, 1, &exact, &mut tx), Ok(60));
}

#[test]
fn a_reader_gets_the_status_only_when_it_asked_for_it() {
    let mut sk = connected();
    assert_eq!(data::recv(&sk, b"pcm", data::SCO_PKT_STATUS_INVALID),
               Some(RxPacket { data: b"pcm".to_vec(), cmsg: None }));
    sk.pkt_status = true;
    assert_eq!(data::recv(&sk, b"pcm", data::SCO_PKT_STATUS_INVALID),
               Some(RxPacket { data: b"pcm".to_vec(),
                               cmsg: Some((BT_SCM_PKT_STATUS, data::SCO_PKT_STATUS_INVALID)) }));
}

#[test]
fn an_empty_packet_is_dropped() {
    let sk = connected();
    assert!(data::recv(&sk, &[], data::SCO_PKT_STATUS_OK).is_none());
}

#[test]
fn the_status_is_the_low_pair_of_the_flag_nibble() {
    assert_eq!(data::status_of(0x0), data::SCO_PKT_STATUS_OK);
    assert_eq!(data::status_of(0x1), data::SCO_PKT_STATUS_INVALID);
    assert_eq!(data::status_of(0x2), data::SCO_PKT_STATUS_NO_DATA);
    assert_eq!(data::status_of(0x3), data::SCO_PKT_STATUS_PARTIAL);
    assert_eq!(data::status_of(0xf), data::SCO_PKT_STATUS_PARTIAL, "the upper bits are reserved");
}
