//! Terminal-binding contract: the device registry, the ioctl codecs and the
//! modem-line mapping in both directions.

use crate::rfcomm::tty::dev::{DevList, DevReq, RfcommDev};
use crate::rfcomm::tty::ioctl::{self, CreateCtx, DevIoctl};
use crate::rfcomm::tty::modem;
use crate::uapi::bt::{BdAddr, BT_CONNECTED, BT_OPEN};
use crate::uapi::rfcomm as u;
use syscall::errno::Errno;

fn req(dev_id: i16, channel: u8) -> DevReq {
    DevReq { dev_id, flags: u::RFCOMM_NOCAP_FLAGS, src: BdAddr([1; 6]), dst: BdAddr([2; 6]), channel }
}

fn ctx(capable: bool) -> CreateCtx {
    CreateCtx { sock_state: BT_CONNECTED, channel_busy: false, capable }
}

#[test]
fn a_negative_identifier_takes_the_lowest_free_one() {
    let mut devs = DevList::new();
    assert_eq!(devs.add(&req(-1, 3), BT_OPEN), Ok(0));
    assert_eq!(devs.add(&req(-1, 3), BT_OPEN), Ok(1));
    assert_eq!(devs.add(&req(5, 3), BT_OPEN), Ok(5));
    assert_eq!(devs.add(&req(-1, 3), BT_OPEN), Ok(2), "the gap is filled before the used one");
}

#[test]
fn a_named_identifier_is_exclusive_and_bounded() {
    let mut devs = DevList::new();
    devs.add(&req(4, 3), BT_OPEN).unwrap();
    assert_eq!(devs.add(&req(4, 3), BT_OPEN), Err(Errno::Eaddrinuse));
    assert_eq!(devs.add(&req(u::RFCOMM_MAX_DEV, 3), BT_OPEN), Err(Errno::Enfile));
    assert!(devs.add(&req(u::RFCOMM_MAX_DEV - 1, 3), BT_OPEN).is_ok());
}

#[test]
fn a_device_keeps_only_the_flags_that_describe_it() {
    let mut devs = DevList::new();
    let mut r = req(-1, 3);
    r.flags = u::RFCOMM_NOCAP_FLAGS | (1 << u::RFCOMM_HANGUP_NOW) | (1 << u::RFCOMM_TTY_ATTACHED);
    let id = devs.add(&r, BT_OPEN).unwrap();
    let d = devs.get(id).unwrap();
    assert_eq!(d.flags, u::RFCOMM_DEV_FLAG_MASK);
    assert!(!d.flag(u::RFCOMM_HANGUP_NOW));
}

#[test]
fn releasing_twice_is_refused() {
    let mut devs = DevList::new();
    let id = devs.add(&req(-1, 3), BT_OPEN).unwrap();
    devs.set_tty_owned(id, true);
    assert!(devs.release(id).is_ok());
    assert_eq!(devs.release(id), Err(Errno::Ealready));
    assert_eq!(devs.release(99), Err(Errno::Enodev));
}

#[test]
fn releasing_an_unowned_device_drops_it() {
    let mut devs = DevList::new();
    let id = devs.add(&req(-1, 3), BT_OPEN).unwrap();
    devs.release(id).unwrap();
    assert!(devs.get(id).is_none());
    assert!(devs.is_empty());
}

#[test]
fn the_privileged_flag_test_is_equality_not_a_subset() {
    assert!(ioctl::flags_permitted(u::RFCOMM_NOCAP_FLAGS, false));
    assert!(!ioctl::flags_permitted(0, false), "no flags at all is still privileged");
    assert!(!ioctl::flags_permitted(1 << u::RFCOMM_REUSE_DLC, false));
    assert!(ioctl::flags_permitted(0, true));
}

#[test]
fn creating_a_device_checks_the_socket_and_the_channel() {
    let mut devs = DevList::new();
    let mut r = req(-1, 3);
    r.flags = 1 << u::RFCOMM_REUSE_DLC;
    assert_eq!(ioctl::create_dev(&mut devs, &r, ctx(false)), Err(Errno::Eperm));

    let mut c = ctx(true);
    c.sock_state = BT_OPEN;
    assert_eq!(ioctl::create_dev(&mut devs, &r, c), Err(Errno::Ebadfd),
               "reusing the socket's own channel needs a connected socket");

    let mut fresh = req(-1, 0);
    fresh.flags = 1 << u::RFCOMM_RELEASE_ONHUP;
    assert_eq!(ioctl::create_dev(&mut devs, &fresh, ctx(true)), Err(Errno::Einval));
    fresh.channel = 3;
    let mut busy = ctx(true);
    busy.channel_busy = true;
    assert_eq!(ioctl::create_dev(&mut devs, &fresh, busy), Err(Errno::Ebusy));
    assert!(ioctl::create_dev(&mut devs, &fresh, ctx(true)).is_ok());
}

#[test]
fn the_request_struct_round_trips_through_its_abi_layout() {
    let r = DevReq { dev_id: -1, flags: 0x0a, src: BdAddr([1, 2, 3, 4, 5, 6]),
                     dst: BdAddr([7, 8, 9, 10, 11, 12]), channel: 9 };
    let mut buf = [0xffu8; u::RFCOMM_DEV_REQ_LEN];
    assert!(ioctl::dev_req_to_wire(&r, &mut buf));
    assert_eq!(ioctl::dev_req_from_wire(&buf), Some(r));
    assert_eq!(buf.len(), 24);
    assert!(ioctl::dev_req_from_wire(&buf[..23]).is_none());
}

#[test]
fn the_info_struct_round_trips_through_its_abi_layout() {
    let mut devs = DevList::new();
    let id = devs.add(&req(-1, 9), BT_CONNECTED).unwrap();
    let di = ioctl::get_dev_info(&devs, id).unwrap();
    assert_eq!(di.state, BT_CONNECTED as u16);
    assert_eq!(di.channel, 9);
    let mut buf = [0xffu8; u::RFCOMM_DEV_INFO_LEN];
    assert!(ioctl::dev_info_to_wire(&di, &mut buf));
    assert_eq!(ioctl::dev_info_from_wire(&buf), Some(di));
    assert_eq!(ioctl::get_dev_info(&devs, 42), Err(Errno::Enodev));
}

#[test]
fn the_device_list_reports_the_count_it_actually_filled() {
    let mut devs = DevList::new();
    for _ in 0..3 { devs.add(&req(-1, 3), BT_OPEN).unwrap(); }
    assert_eq!(ioctl::get_dev_list(&devs, 0), Err(Errno::Einval));
    assert_eq!(ioctl::get_dev_list(&devs, ioctl::DEV_LIST_MAX + 1), Err(Errno::Einval));
    let all = ioctl::get_dev_list(&devs, 10).unwrap();
    assert_eq!(all.len(), 3);
    let capped = ioctl::get_dev_list(&devs, 2).unwrap();
    assert_eq!(capped.len(), 2);
    let wire = ioctl::dev_list_to_wire(&capped);
    assert_eq!(&wire[0..2], &2u16.to_le_bytes());
    assert_eq!(wire.len(), u::RFCOMM_DEV_LIST_HDR_LEN + 2 * u::RFCOMM_DEV_INFO_LEN);
    assert_eq!(ioctl::dev_info_from_wire(&wire[u::RFCOMM_DEV_LIST_HDR_LEN..]), Some(capped[0]));
}

#[test]
fn the_ioctl_numbers_classify_and_the_steal_number_is_refused() {
    assert_eq!(ioctl::classify(u::RFCOMMCREATEDEV), Ok(DevIoctl::Create));
    assert_eq!(ioctl::classify(u::RFCOMMRELEASEDEV), Ok(DevIoctl::Release));
    assert_eq!(ioctl::classify(u::RFCOMMGETDEVLIST), Ok(DevIoctl::GetList));
    assert_eq!(ioctl::classify(u::RFCOMMGETDEVINFO), Ok(DevIoctl::GetInfo));
    assert_eq!(ioctl::classify(u::RFCOMMSTEALDLC), Err(Errno::Einval));
    assert_eq!(ioctl::classify(0), Err(Errno::Einval));
}

#[test]
fn the_ioctl_numbers_are_the_encodings_the_abi_defines() {
    // Direction, size and type are packed with the command number.
    let iow = |nr: u32| 0x4000_0000 | (4 << 16) | (u32::from(b'R') << 8) | nr;
    let ior = |nr: u32| 0x8000_0000 | (4 << 16) | (u32::from(b'R') << 8) | nr;
    assert_eq!(u::RFCOMMCREATEDEV, iow(200));
    assert_eq!(u::RFCOMMRELEASEDEV, iow(201));
    assert_eq!(u::RFCOMMGETDEVLIST, ior(210));
    assert_eq!(u::RFCOMMGETDEVINFO, ior(211));
    assert_eq!(u::RFCOMMSTEALDLC, iow(220));
}

#[test]
fn the_peers_signals_become_the_terminals_input_lines() {
    assert_eq!(modem::v24_to_tiocm(u::RFCOMM_V24_RTC), modem::TIOCM_DSR);
    assert_eq!(modem::v24_to_tiocm(u::RFCOMM_V24_RTR), modem::TIOCM_CTS);
    assert_eq!(modem::v24_to_tiocm(u::RFCOMM_V24_IC), modem::TIOCM_RI);
    assert_eq!(modem::v24_to_tiocm(u::RFCOMM_V24_DV), modem::TIOCM_CD);
    let all = u::RFCOMM_V24_RTC | u::RFCOMM_V24_RTR | u::RFCOMM_V24_IC | u::RFCOMM_V24_DV;
    assert_eq!(modem::v24_to_tiocm(all),
               modem::TIOCM_DSR | modem::TIOCM_CTS | modem::TIOCM_RI | modem::TIOCM_CD);
    assert_eq!(modem::v24_to_tiocm(u::RFCOMM_V24_FC), 0, "the flow bit is not a modem line");
}

#[test]
fn tiocmget_keeps_the_linux_raw_local_output_mask() {
    let remote = modem::TIOCM_CTS | modem::TIOCM_CD;
    assert_eq!(modem::tiocmget(u::RFCOMM_V24_RTC, remote), modem::TIOCM_RTS | remote,
               "Linux masks the local V.24 byte; it does not translate RTC to DSR here");
    assert_eq!(modem::tiocmget(u::RFCOMM_V24_FC, remote), modem::TIOCM_DTR | remote,
               "the raw flow bit aliases DTR in the reference ABI");
}

#[test]
fn the_terminals_output_lines_become_the_peers_signals() {
    let v = modem::apply_tiocm(0, modem::TIOCM_DTR, 0);
    assert_eq!(v, u::RFCOMM_V24_RTC);
    let v = modem::apply_tiocm(v, modem::TIOCM_RTS, 0);
    assert_eq!(v, u::RFCOMM_V24_RTC | u::RFCOMM_V24_RTR);
    let v = modem::apply_tiocm(v, 0, modem::TIOCM_DTR);
    assert_eq!(v, u::RFCOMM_V24_RTR);
    let v = modem::apply_tiocm(v, 0, modem::TIOCM_RTS);
    assert_eq!(v, 0);
    assert_eq!(modem::apply_tiocm(u::RFCOMM_V24_DV, modem::TIOCM_DTR, 0),
               u::RFCOMM_V24_DV | u::RFCOMM_V24_RTC, "the peer's inputs are untouched");
}

#[test]
fn a_dropped_carrier_is_detected_once() {
    let mut dev = RfcommDev { id: 0, flags: 0, status: 0, src: BdAddr([0; 6]), dst: BdAddr([0; 6]),
                              channel: 3, dlc_state: BT_CONNECTED, modem_status: 0 };
    assert!(!dev.set_remote_signals(u::RFCOMM_V24_DV));
    assert_eq!(dev.modem_status & modem::TIOCM_CD, modem::TIOCM_CD);
    assert!(dev.set_remote_signals(0), "losing the carrier is reported");
    assert!(!dev.set_remote_signals(0), "and not reported again");
}
