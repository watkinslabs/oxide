// The user-notification ABI, as a program built against the seccomp headers
// sees it. These numbers ARE the contract: a wrong bit in one of them makes
// every supervisor's ioctl fail with ENOTTY or land on another command.

use super::*;

#[test]
fn the_five_listener_commands_encode_exactly_as_the_headers_do() {
    // dir<<30 | size<<16 | '!'<<8 | nr, with '!' = 0x21.
    assert_eq!(IOCTL_NOTIF_RECV,      0xC050_2100);
    assert_eq!(IOCTL_NOTIF_SEND,      0xC018_2101);
    assert_eq!(IOCTL_NOTIF_ID_VALID,  0x4008_2102);
    assert_eq!(IOCTL_NOTIF_ADDFD,     0x4018_2103);
    assert_eq!(IOCTL_NOTIF_SET_FLAGS, 0x4008_2104);
    // The first release encoded ID_VALID's direction backwards. Programs
    // built against that header still send it, so it stays accepted.
    assert_eq!(IOCTL_NOTIF_ID_VALID_WRONG_DIR, 0x8008_2102);
}

#[test]
fn the_three_exchanged_structures_have_their_documented_sizes() {
    assert_eq!(NOTIF_BYTES, 80);
    assert_eq!(NOTIF_RESP_BYTES, 24);
    assert_eq!(ADDFD_SIZE_VER0, 24);
}

// An extensible-argument command is matched with its size and direction
// stripped, so a program built against a LARGER addfd structure still reaches
// the addfd handler instead of falling through to the unknown-command answer.
#[test]
fn an_extensible_command_matches_whatever_payload_size_it_declares() {
    let bigger = (IOCTL_NOTIF_ADDFD & !(0x3FFF << 16)) | (64 << 16);
    assert_eq!(ea_ioctl(bigger), ea_ioctl(IOCTL_NOTIF_ADDFD));
    assert_eq!(ioc_size(bigger), 64);
    assert_eq!(ioc_size(IOCTL_NOTIF_ADDFD), ADDFD_SIZE_VER0);
    // Stripping must not merge two DIFFERENT commands.
    assert_ne!(ea_ioctl(IOCTL_NOTIF_ADDFD), ea_ioctl(IOCTL_NOTIF_SET_FLAGS));
    assert_ne!(ea_ioctl(IOCTL_NOTIF_RECV), ea_ioctl(IOCTL_NOTIF_SEND));
}

#[test]
fn a_notification_lays_out_id_pid_flags_then_the_filter_data() {
    let d = SeccompData { nr: 42, arch: 0xC000_003E, ip: 0x4142_4344, args: [1, 2, 3, 4, 5, 6] };
    let b = encode_notif(0x1122_3344_5566_7788, 4321, 0, &d);
    assert_eq!(&b[0..8], &0x1122_3344_5566_7788u64.to_le_bytes());
    assert_eq!(&b[8..12], &4321u32.to_le_bytes());
    assert_eq!(&b[12..16], &0u32.to_le_bytes());
    assert_eq!(&b[16..], &d.bytes());
}

#[test]
fn a_response_decodes_id_value_error_then_flags() {
    let mut b = [0u8; NOTIF_RESP_BYTES as usize];
    b[0..8].copy_from_slice(&7u64.to_le_bytes());
    b[8..16].copy_from_slice(&(-1i64).to_le_bytes());
    b[16..20].copy_from_slice(&(-13i32).to_le_bytes());
    b[20..24].copy_from_slice(&USER_NOTIF_FLAG_CONTINUE.to_le_bytes());
    assert_eq!(NotifResp::decode(&b),
               NotifResp { id: 7, val: -1, error: -13, flags: USER_NOTIF_FLAG_CONTINUE });
}

#[test]
fn an_injection_request_decodes_id_flags_srcfd_newfd_then_newfd_flags() {
    let mut b = [0u8; ADDFD_SIZE_VER0 as usize];
    b[0..8].copy_from_slice(&9u64.to_le_bytes());
    b[8..12].copy_from_slice(&ADDFD_FLAG_SETFD.to_le_bytes());
    b[12..16].copy_from_slice(&5u32.to_le_bytes());
    b[16..20].copy_from_slice(&11u32.to_le_bytes());
    b[20..24].copy_from_slice(&O_CLOEXEC.to_le_bytes());
    assert_eq!(AddfdReq::decode(&b), AddfdReq {
        id: 9, flags: ADDFD_FLAG_SETFD, srcfd: 5, newfd: 11, newfd_flags: O_CLOEXEC });
}
