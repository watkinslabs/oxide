//! Codec round trips and refusals.

use crate::uapi::bt::{BDADDR_LE_RANDOM, BdAddr};
use crate::uapi::smp::*;
use crate::smp::pdu::*;

fn sample_pairing() -> PairingCmd {
    PairingCmd {
        io_capability: SMP_IO_KEYBOARD_DISPLAY,
        oob_flag: SMP_OOB_PRESENT,
        auth_req: SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC,
        max_key_size: SMP_MAX_ENC_KEY_SIZE,
        init_key_dist: SMP_DIST_ENC_KEY | SMP_DIST_ID_KEY,
        resp_key_dist: SMP_DIST_SIGN,
    }
}

fn key(seed: u8) -> [u8; SMP_KEY_LEN] {
    let mut k = [0u8; SMP_KEY_LEN];
    for (i, b) in k.iter_mut().enumerate() { *b = seed.wrapping_add(i as u8); }
    k
}

fn coord(seed: u8) -> [u8; SMP_PUBKEY_COORD_LEN] {
    let mut c = [0u8; SMP_PUBKEY_COORD_LEN];
    for (i, b) in c.iter_mut().enumerate() { *b = seed ^ (i as u8); }
    c
}

fn every_pdu() -> [Pdu; 14] {
    [
        Pdu::PairingReq(sample_pairing()),
        Pdu::PairingRsp(sample_pairing()),
        Pdu::Confirm(key(0x10)),
        Pdu::Random(key(0x20)),
        Pdu::Fail(SMP_CONFIRM_FAILED),
        Pdu::EncryptInfo(key(0x30)),
        Pdu::InitiatorIdent { ediv: 0xbeef, rand: 0x0123_4567_89ab_cdef },
        Pdu::IdentInfo(key(0x40)),
        Pdu::IdentAddrInfo { addr_type: BDADDR_LE_RANDOM, addr: BdAddr([6, 5, 4, 3, 2, 1]) },
        Pdu::SignInfo(key(0x50)),
        Pdu::SecurityReq(SMP_AUTH_MITM),
        Pdu::PublicKey { x: coord(0x60), y: coord(0x70) },
        Pdu::DhkeyCheck(key(0x80)),
        Pdu::KeypressNotify(SMP_KEYPRESS_ENTRY_COMPLETED),
    ]
}

#[test]
fn every_command_round_trips() {
    let mut buf = [0u8; SMP_PDU_MAX];
    for pdu in every_pdu() {
        let n = pdu.encode(&mut buf).expect("encodes");
        assert_eq!(n, pdu.encoded_len());
        assert_eq!(decode(&buf[..n]), Ok(pdu), "code {:#x}", pdu.code());
    }
}

#[test]
fn every_command_code_is_distinct_and_in_range() {
    let mut seen = [false; 256];
    for pdu in every_pdu() {
        let c = pdu.code();
        assert!(c >= SMP_CMD_PAIRING_REQ && c <= SMP_CMD_MAX, "code {:#x}", c);
        assert!(!seen[c as usize], "duplicate code {:#x}", c);
        seen[c as usize] = true;
    }
}

#[test]
fn encoded_widths_match_the_wire_definitions() {
    let expect: [(u8, usize); 14] = [
        (SMP_CMD_PAIRING_REQ, SMP_PAIRING_LEN),
        (SMP_CMD_PAIRING_RSP, SMP_PAIRING_LEN),
        (SMP_CMD_PAIRING_CONFIRM, SMP_CONFIRM_LEN),
        (SMP_CMD_PAIRING_RANDOM, SMP_RANDOM_LEN),
        (SMP_CMD_PAIRING_FAIL, SMP_FAIL_LEN),
        (SMP_CMD_ENCRYPT_INFO, SMP_ENCRYPT_INFO_LEN),
        (SMP_CMD_INITIATOR_IDENT, SMP_INITIATOR_IDENT_LEN),
        (SMP_CMD_IDENT_INFO, SMP_IDENT_INFO_LEN),
        (SMP_CMD_IDENT_ADDR_INFO, SMP_IDENT_ADDR_LEN),
        (SMP_CMD_SIGN_INFO, SMP_SIGN_INFO_LEN),
        (SMP_CMD_SECURITY_REQ, SMP_SECURITY_REQ_LEN),
        (SMP_CMD_PUBLIC_KEY, SMP_PUBLIC_KEY_LEN),
        (SMP_CMD_DHKEY_CHECK, SMP_DHKEY_CHECK_LEN),
        (SMP_CMD_KEYPRESS_NOTIFY, SMP_KEYPRESS_LEN),
    ];
    for (code, len) in expect {
        assert_eq!(payload_len(code), Some(len), "code {:#x}", code);
    }
}

#[test]
fn a_short_payload_is_refused() {
    let mut buf = [0u8; SMP_PDU_MAX];
    for pdu in every_pdu() {
        let n = pdu.encode(&mut buf).unwrap();
        for short in 1..n {
            assert_eq!(decode(&buf[..short]), Err(DecodeErr::BadLength),
                       "code {:#x} truncated to {}", pdu.code(), short);
        }
    }
}

#[test]
fn trailing_bytes_are_ignored() {
    // A peer built to a later revision may append; the frame still decodes as
    // the revision this host knows.
    let mut buf = [0u8; SMP_PDU_MAX + 8];
    for pdu in every_pdu() {
        let n = pdu.encode(&mut buf).unwrap();
        buf[n..n + 8].fill(0xff);
        assert_eq!(decode(&buf[..n + 8]), Ok(pdu), "code {:#x}", pdu.code());
    }
}

#[test]
fn an_empty_frame_carries_no_code() {
    assert_eq!(decode(&[]), Err(DecodeErr::Empty));
    assert_eq!(err_reason(DecodeErr::Empty), None);
}

#[test]
fn a_code_past_the_range_is_dropped_and_one_inside_it_is_answered() {
    assert_eq!(decode(&[SMP_CMD_MAX + 1]), Err(DecodeErr::Unknown));
    assert_eq!(decode(&[0xff, 0, 0]), Err(DecodeErr::Unknown));
    assert_eq!(err_reason(DecodeErr::Unknown), None);
    // Zero is inside the range but names no command.
    assert_eq!(decode(&[0x00]), Err(DecodeErr::NotSupported));
    assert_eq!(err_reason(DecodeErr::NotSupported), Some(SMP_CMD_NOTSUPP));
    assert_eq!(payload_len(0x00), None);
    assert_eq!(err_reason(DecodeErr::BadLength), Some(SMP_INVALID_PARAMS));
}

#[test]
fn a_buffer_too_small_to_encode_is_refused() {
    let pdu = Pdu::PublicKey { x: coord(1), y: coord(2) };
    let mut small = [0u8; SMP_PDU_MAX - 1];
    assert_eq!(pdu.encode(&mut small), None);
}

#[test]
fn the_pairing_body_survives_its_own_round_trip() {
    let c = sample_pairing();
    assert_eq!(PairingCmd::from_bytes(&c.to_bytes()), c);
    // Field order on the wire is capability, out-of-band flag, requirements,
    // key size, then the two distribution masks.
    assert_eq!(c.to_bytes(), [
        c.io_capability, c.oob_flag, c.auth_req,
        c.max_key_size, c.init_key_dist, c.resp_key_dist,
    ]);
}

#[test]
fn the_identifier_frame_is_little_endian() {
    let pdu = Pdu::InitiatorIdent { ediv: 0x0102, rand: 0x0807_0605_0403_0201 };
    let mut buf = [0u8; SMP_PDU_MAX];
    let n = pdu.encode(&mut buf).unwrap();
    assert_eq!(&buf[..n], &[
        SMP_CMD_INITIATOR_IDENT, 0x02, 0x01,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);
}

#[test]
fn the_public_key_frame_is_x_then_y() {
    let x = coord(0xaa);
    let y = coord(0x55);
    let mut buf = [0u8; SMP_PDU_MAX];
    let n = Pdu::PublicKey { x, y }.encode(&mut buf).unwrap();
    assert_eq!(n, 1 + 64);
    assert_eq!(&buf[1..33], &x);
    assert_eq!(&buf[33..65], &y);
}
