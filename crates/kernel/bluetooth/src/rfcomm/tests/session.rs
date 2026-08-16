//! Session contract: the link-control handshake, the multiplexer command
//! answers, and the credit-paced transmit pass.

use crate::rfcomm::frame;
use crate::rfcomm::link::{DlcEvent, FrameLog};
use crate::rfcomm::mcc::{self, Mcc, Msc, Pn};
use crate::rfcomm::session::Session;
use crate::uapi::bt::{BT_CONNECTED, BT_CONFIG, BT_CONNECT};
use crate::uapi::rfcomm as u;
use syscall::errno::Errno;

/// The multiplexer command a collected frame carries, if it is one.
fn as_mcc(bytes: &[u8]) -> Option<mcc::MccFrame> {
    let f = frame::decode(bytes).ok()?;
    if f.dlci() != 0 || f.ftype() != u::RFCOMM_UIH { return None; }
    mcc::decode(f.payload)
}

/// One frame from the peer, built with the peer's own addressing.
fn peer_cmd(initiator_here: bool, dlci: u8, ftype: u8) -> alloc::vec::Vec<u8> {
    // The peer is the opposite end, so its command bit is the opposite one.
    frame::encode_cmd(u::addr(!initiator_here, dlci), ftype, true)
}

fn peer_mcc(initiator_here: bool, cr: bool, cmd: &Mcc) -> alloc::vec::Vec<u8> {
    mcc::encode(u::addr(!initiator_here, 0), cr, cmd)
}

#[test]
fn opening_a_channel_validates_it() {
    let mut s = Session::new(true);
    let mut h = FrameLog::new();
    assert_eq!(s.open(0, &mut h), Err(Errno::Einval));
    assert_eq!(s.open(31, &mut h), Err(Errno::Einval));
    let dlci = s.open(3, &mut h).expect("a data channel opens");
    assert_eq!(dlci, u::dlci(0, 3));
    assert_eq!(s.open(3, &mut h), Err(Errno::Ebusy));
}

#[test]
fn an_initiator_walks_the_handshake_to_connected() {
    let mut s = Session::new(true);
    let mut h = FrameLog::new();
    s.connect(&mut h);
    let f = frame::decode(&h.frames[0]).unwrap();
    assert_eq!(f.ftype(), u::RFCOMM_SABM);
    assert_eq!(f.dlci(), 0);

    let dlci = s.open(3, &mut h).unwrap();
    assert_eq!(s.dlc(dlci).unwrap().state, BT_CONFIG);

    // The peer acknowledges the control channel; the DLC's negotiation starts.
    h.clear();
    s.recv(&peer_cmd(true, 0, u::RFCOMM_UA), &mut h).unwrap();
    assert_eq!(s.state, BT_CONNECTED);
    let m = as_mcc(&h.frames[0]).expect("a parameter negotiation follows");
    assert!(m.cr);
    let Mcc::Pn(pn) = m.cmd else { panic!("expected a parameter negotiation") };
    assert_eq!(pn.dlci, dlci);
    assert_eq!(pn.flow_ctrl, u::RFCOMM_PN_CFC_REQ);

    // The peer answers it; a set-mode command follows.
    h.clear();
    let rsp = Pn { dlci, flow_ctrl: u::RFCOMM_PN_CFC_RSP, priority: 7, ack_timer: 0,
                   mtu: 127, max_retrans: 0, credits: 7 };
    s.recv(&peer_mcc(true, false, &Mcc::Pn(rsp)), &mut h).unwrap();
    assert_eq!(s.dlc(dlci).unwrap().state, BT_CONNECT);
    assert_eq!(frame::decode(&h.frames[0]).unwrap().ftype(), u::RFCOMM_SABM);
    assert!(s.dlc(dlci).unwrap().credit.enabled());
    assert_eq!(s.dlc(dlci).unwrap().credit.tx_credits, 7);

    // The peer accepts the DLC; the modem status is reported.
    h.clear();
    s.recv(&peer_cmd(true, dlci, u::RFCOMM_UA), &mut h).unwrap();
    assert_eq!(s.dlc(dlci).unwrap().state, BT_CONNECTED);
    assert!(matches!(as_mcc(&h.frames[0]).unwrap().cmd, Mcc::Msc(_)));
    assert!(s.events.contains(&DlcEvent::StateChange { dlci, state: BT_CONNECTED, err: 0 }));
}

#[test]
fn a_responder_accepts_a_channel_it_listens_on() {
    let mut s = Session::new(false);
    let mut h = FrameLog::listening(&[5]);
    s.recv(&peer_cmd(false, 0, u::RFCOMM_SABM), &mut h).unwrap();
    assert_eq!(s.state, BT_CONNECTED);
    assert_eq!(frame::decode(&h.frames[0]).unwrap().ftype(), u::RFCOMM_UA);

    h.clear();
    let dlci = u::dlci(u::session_dir(false), 5);
    s.recv(&peer_cmd(false, dlci, u::RFCOMM_SABM), &mut h).unwrap();
    assert_eq!(frame::decode(&h.frames[0]).unwrap().ftype(), u::RFCOMM_UA);
    assert_eq!(s.dlc(dlci).unwrap().state, BT_CONNECTED);
}

#[test]
fn a_responder_refuses_a_channel_nobody_listens_on() {
    let mut s = Session::new(false);
    let mut h = FrameLog::new();
    s.recv(&peer_cmd(false, 0, u::RFCOMM_SABM), &mut h).unwrap();
    h.clear();
    s.recv(&peer_cmd(false, 8, u::RFCOMM_SABM), &mut h).unwrap();
    assert_eq!(frame::decode(&h.frames[0]).unwrap().ftype(), u::RFCOMM_DM);
    assert!(s.dlc(8).is_none());
}

#[test]
fn a_refusal_during_setup_reports_connection_refused() {
    let mut s = Session::new(true);
    let mut h = FrameLog::new();
    s.connect(&mut h);
    let dlci = s.open(3, &mut h).unwrap();
    s.recv(&peer_cmd(true, 0, u::RFCOMM_UA), &mut h).unwrap();
    s.recv(&frame::encode_cmd(u::addr(false, dlci), u::RFCOMM_DM, true), &mut h).unwrap();
    assert!(s.events.contains(&DlcEvent::StateChange {
        dlci, state: crate::uapi::bt::BT_CLOSED, err: Errno::Econnrefused.as_i32() }));
    assert!(s.dlc(dlci).is_none());
}

#[test]
fn a_modem_status_request_is_answered_and_recorded() {
    let (mut s, mut h, dlci) = connected();
    h.clear();
    let v24 = u::RFCOMM_V24_RTC | u::RFCOMM_V24_RTR | u::RFCOMM_V24_DV;
    s.recv(&peer_mcc(true, true, &Mcc::Msc(Msc { dlci, v24_sig: v24 })), &mut h).unwrap();
    let m = as_mcc(&h.frames[0]).unwrap();
    assert!(!m.cr, "a request is answered with a response");
    assert_eq!(s.dlc(dlci).unwrap().remote_v24_sig, v24 | 0x01);
    assert_eq!(s.dlc(dlci).unwrap().mscex & u::RFCOMM_MSCEX_RX, u::RFCOMM_MSCEX_RX);
}

#[test]
fn an_unknown_command_is_refused_by_type() {
    let (mut s, mut h, _) = connected();
    h.clear();
    s.recv(&peer_mcc(true, true, &Mcc::Unknown(0x11)), &mut h).unwrap();
    let m = as_mcc(&h.frames[0]).unwrap();
    assert_eq!(m.cmd, Mcc::Nsc(u::mcc_type(true, 0x11)));
}

#[test]
fn a_test_command_is_echoed_and_flow_commands_are_answered() {
    let (mut s, mut h, _) = connected();
    h.clear();
    s.recv(&peer_mcc(true, true, &Mcc::Test(alloc::vec![9, 8, 7])), &mut h).unwrap();
    assert_eq!(as_mcc(&h.frames[0]).unwrap().cmd, Mcc::Test(alloc::vec![9, 8, 7]));

    h.clear();
    s.recv(&peer_mcc(true, true, &Mcc::Fcoff), &mut h).unwrap();
    assert!(s.tx_throttled);
    assert_eq!(as_mcc(&h.frames[0]).unwrap().cmd, Mcc::Fcoff);
    h.clear();
    s.recv(&peer_mcc(true, true, &Mcc::Fcon), &mut h).unwrap();
    assert!(!s.tx_throttled);
}

/// A session with one DLC connected, credit flow on, and the modem-status
/// exchange complete in both directions.
fn connected() -> (Session, FrameLog, u8) {
    let mut s = Session::new(true);
    let mut h = FrameLog::new();
    s.connect(&mut h);
    let dlci = s.open(3, &mut h).unwrap();
    s.recv(&peer_cmd(true, 0, u::RFCOMM_UA), &mut h).unwrap();
    let rsp = Pn { dlci, flow_ctrl: u::RFCOMM_PN_CFC_RSP, priority: 7, ack_timer: 0,
                   mtu: 127, max_retrans: 0, credits: 3 };
    s.recv(&peer_mcc(true, false, &Mcc::Pn(rsp)), &mut h).unwrap();
    s.recv(&peer_cmd(true, dlci, u::RFCOMM_UA), &mut h).unwrap();
    // Both directions of the modem-status exchange.
    let v24 = u::RFCOMM_V24_RTC | u::RFCOMM_V24_RTR | u::RFCOMM_V24_DV;
    s.recv(&peer_mcc(true, false, &Mcc::Msc(Msc { dlci, v24_sig: v24 })), &mut h).unwrap();
    s.recv(&peer_mcc(true, true, &Mcc::Msc(Msc { dlci, v24_sig: v24 })), &mut h).unwrap();
    assert!(s.dlc_ready(dlci));
    (s, h, dlci)
}

#[test]
fn a_transmit_pass_spends_credits_and_stops_at_zero() {
    let (mut s, mut h, dlci) = connected();
    h.clear();
    assert_eq!(s.dlc(dlci).unwrap().credit.tx_credits, 3);
    for _ in 0..5 { s.send_data(dlci, b"abc").unwrap(); }
    s.process(&mut h);
    let data_frames = h.frames.iter().filter(|f| frame::decode(f).unwrap().payload == b"abc").count();
    assert_eq!(data_frames, 3, "only the granted credits are spent");
    assert_eq!(s.dlc(dlci).unwrap().tx_queue.len(), 2);
    assert!(s.dlc(dlci).unwrap().credit.tx_throttled);

    // Releasing the throttle without a grant releases nothing: the credit count
    // is what pays for a frame.
    h.clear();
    s.dlc_mut(dlci).unwrap().credit.tx_throttled = false;
    s.process(&mut h);
    assert_eq!(h.frames.iter().filter(|f| frame::decode(f).unwrap().payload == b"abc").count(), 0);
    assert_eq!(s.dlc(dlci).unwrap().tx_queue.len(), 2);

    // A grant releases exactly what it pays for.
    h.clear();
    let grant = frame::encode_uih(u::addr(false, dlci), true, &[2]);
    s.recv(&grant, &mut h).unwrap();
    s.process(&mut h);
    let data_frames = h.frames.iter().filter(|f| frame::decode(f).unwrap().payload == b"abc").count();
    assert_eq!(data_frames, 2);
    assert!(s.dlc(dlci).unwrap().tx_queue.is_empty());
}

#[test]
fn a_receive_top_up_is_sent_as_a_credit_frame() {
    let (mut s, mut h, dlci) = connected();
    let ceiling = s.dlc(dlci).unwrap().credit.ceiling();
    s.dlc_mut(dlci).unwrap().credit.rx_credits = 1;
    h.clear();
    s.process(&mut h);
    let f = frame::decode(&h.frames[0]).unwrap();
    assert!(f.pf(), "a credit frame carries the poll bit");
    assert_eq!(f.payload, &[(ceiling - 1) as u8]);
    assert_eq!(s.dlc(dlci).unwrap().credit.rx_credits, ceiling);
}

#[test]
fn received_data_reaches_the_reader_without_its_credit_byte() {
    let (mut s, mut h, dlci) = connected();
    s.events.clear();
    let f = frame::encode_uih(u::addr(false, dlci), true, b"\x05hello");
    s.recv(&f, &mut h).unwrap();
    assert_eq!(s.events, alloc::vec![DlcEvent::Data { dlci, data: b"hello".to_vec() }]);
    assert_eq!(s.dlc(dlci).unwrap().credit.tx_credits, 3 + 5);
}

#[test]
fn data_is_split_at_the_negotiated_mtu() {
    let (mut s, mut h, dlci) = connected();
    s.dlc_mut(dlci).unwrap().mtu = 4;
    s.send_data(dlci, b"abcdefghij").unwrap();
    assert_eq!(s.dlc(dlci).unwrap().tx_queue.len(), 3);
    let _ = &mut h;
}

#[test]
fn sending_on_a_channel_that_is_not_up_is_refused() {
    let mut s = Session::new(true);
    let mut h = FrameLog::new();
    let dlci = s.open(3, &mut h).unwrap();
    assert_eq!(s.send_data(dlci, b"x"), Err(Errno::Enotconn));
    assert_eq!(s.send_data(99, b"x"), Err(Errno::Enotconn));
}

#[test]
fn a_bad_check_byte_is_reported_and_acted_on_by_nobody() {
    let (mut s, mut h, dlci) = connected();
    h.clear();
    s.events.clear();
    let mut f = frame::encode_uih(u::addr(false, dlci), false, b"hello");
    f[0] ^= 0x08;
    assert!(s.recv(&f, &mut h).is_err());
    assert!(s.events.is_empty());
    assert!(h.is_empty());
}

#[test]
fn a_port_negotiation_request_is_answered() {
    let (mut s, mut h, dlci) = connected();
    h.clear();
    let r = crate::rfcomm::mcc::Rpn {
        dlci, bit_rate: u::RFCOMM_RPN_BR_19200,
        line_settings: u::rpn_line_settings(u::RFCOMM_RPN_DATA_8, u::RFCOMM_RPN_STOP_1, u::RFCOMM_RPN_PARITY_NONE),
        flow_ctrl: u::RFCOMM_RPN_FLOW_NONE, xon_char: u::RFCOMM_RPN_XON_CHAR,
        xoff_char: u::RFCOMM_RPN_XOFF_CHAR, param_mask: u::RFCOMM_RPN_PM_BITRATE,
    };
    s.recv(&peer_mcc(true, true, &Mcc::Rpn(r)), &mut h).unwrap();
    let m = as_mcc(&h.frames[0]).unwrap();
    assert!(!m.cr);
    let Mcc::Rpn(reply) = m.cmd else { panic!("expected a port negotiation") };
    assert_ne!(reply.param_mask & u::RFCOMM_RPN_PM_BITRATE, 0);
    assert_eq!(s.dlc(dlci).unwrap().port.bit_rate, u::RFCOMM_RPN_BR_19200);
}

#[test]
fn a_line_status_request_is_answered_and_reported() {
    let (mut s, mut h, dlci) = connected();
    h.clear();
    s.events.clear();
    s.recv(&peer_mcc(true, true, &Mcc::Rls(crate::rfcomm::mcc::Rls { dlci, status: 0x0b })), &mut h).unwrap();
    assert_eq!(as_mcc(&h.frames[0]).unwrap().cmd,
               Mcc::Rls(crate::rfcomm::mcc::Rls { dlci, status: 0x0b }));
    assert!(s.events.contains(&DlcEvent::LineStatus { dlci, status: 0x0b }));
}

#[test]
fn closing_a_connected_channel_disconnects_it_on_the_wire() {
    let (mut s, mut h, dlci) = connected();
    h.clear();
    s.close_dlc(dlci, 0, &mut h);
    assert_eq!(frame::decode(&h.frames[0]).unwrap().ftype(), u::RFCOMM_DISC);
    s.recv(&peer_cmd(true, dlci, u::RFCOMM_UA), &mut h).unwrap();
    assert!(s.dlc(dlci).is_none());
}
