//! RFCOMM ABI constants: the numbers and the field packing they define.

use crate::uapi::rfcomm::*;

#[test]
fn the_frame_and_command_types_are_the_ones_the_abi_defines() {
    assert_eq!((RFCOMM_SABM, RFCOMM_DISC, RFCOMM_UA, RFCOMM_DM, RFCOMM_UIH),
               (0x2f, 0x43, 0x63, 0x0f, 0xef));
    assert_eq!((RFCOMM_TEST, RFCOMM_FCON, RFCOMM_FCOFF, RFCOMM_MSC), (0x08, 0x28, 0x18, 0x38));
    assert_eq!((RFCOMM_RPN, RFCOMM_RLS, RFCOMM_PN, RFCOMM_NSC), (0x24, 0x14, 0x20, 0x04));
}

#[test]
fn masking_the_poll_bit_out_of_a_control_byte_leaves_the_type() {
    // The poll/final bit is the one bit the type mask drops.
    for ty in [RFCOMM_SABM, RFCOMM_DISC, RFCOMM_UA, RFCOMM_DM, RFCOMM_UIH] {
        assert_eq!(get_type(ctrl(ty, true)), ty);
        assert_eq!(ctrl(ty, true) ^ ctrl(ty, false), 0x10);
    }
}

#[test]
fn the_length_field_widens_past_what_one_byte_holds() {
    for len in 0..=RFCOMM_LEN8_MAX {
        let b = len8(len);
        assert!(test_ea(b));
        assert_eq!(get_len8(b), len);
    }
    for len in [128usize, 200, 300, 1000, 16383] {
        let (lo, hi) = (len16_lo(len), len16_hi(len));
        assert!(!test_ea(lo));
        assert_eq!(get_len16(lo, hi), len);
    }
}

#[test]
fn the_credit_and_flow_constants_are_the_ones_the_abi_defines() {
    assert_eq!(RFCOMM_DEFAULT_MTU, 127);
    assert_eq!(RFCOMM_DEFAULT_CREDITS, 7);
    assert_eq!(RFCOMM_MAX_CREDITS, 40);
    assert_eq!(RFCOMM_CFC_ENABLED, RFCOMM_MAX_CREDITS as i16);
    assert_eq!(RFCOMM_CFC_DISABLED, 0);
    assert_eq!(RFCOMM_CFC_UNKNOWN, -1);
    assert_eq!((RFCOMM_PN_CFC_REQ, RFCOMM_PN_CFC_RSP), (0xf0, 0xe0));
}

#[test]
fn the_modem_status_exchange_completes_in_two_directions() {
    assert_eq!(RFCOMM_MSCEX_OK, RFCOMM_MSCEX_TX | RFCOMM_MSCEX_RX);
    assert_eq!(RFCOMM_MSCEX_OK, 3);
}

#[test]
fn the_signal_and_port_constants_are_the_ones_the_abi_defines() {
    assert_eq!((RFCOMM_V24_FC, RFCOMM_V24_RTC, RFCOMM_V24_RTR, RFCOMM_V24_IC, RFCOMM_V24_DV),
               (0x02, 0x04, 0x08, 0x40, 0x80));
    assert_eq!(RFCOMM_RPN_PM_ALL, 0x3F7F);
    assert_eq!(RFCOMM_RPN_PM_FLOW, 0x3F00);
    assert_eq!((RFCOMM_RPN_XON_CHAR, RFCOMM_RPN_XOFF_CHAR), (0x11, 0x13));
    assert_eq!(RFCOMM_RPN_BR_230400, 0x8);
    assert_eq!(RFCOMM_RPN_PARITY_SPACE, 0x7);
}

#[test]
fn the_flag_positions_are_the_ones_the_abi_defines() {
    assert_eq!((RFCOMM_RX_THROTTLED, RFCOMM_TX_THROTTLED, RFCOMM_TIMED_OUT), (0, 1, 2));
    assert_eq!((RFCOMM_MSC_PENDING, RFCOMM_SEC_PENDING, RFCOMM_AUTH_PENDING), (3, 4, 5));
    assert_eq!((RFCOMM_AUTH_ACCEPT, RFCOMM_AUTH_REJECT, RFCOMM_DEFER_SETUP, RFCOMM_ENC_DROP),
               (6, 7, 8, 9));
    assert_eq!(RFCOMM_SCHED_WAKEUP, 31);
    assert_eq!((RFCOMM_REUSE_DLC, RFCOMM_RELEASE_ONHUP, RFCOMM_HANGUP_NOW, RFCOMM_TTY_ATTACHED),
               (0, 1, 2, 3));
    assert_eq!((RFCOMM_DEV_RELEASED, RFCOMM_TTY_OWNED), (0, 1));
    assert_eq!(RFCOMM_NOCAP_FLAGS, 0b11);
}

#[test]
fn the_link_mode_bits_and_timeouts_are_the_ones_the_abi_defines() {
    assert_eq!((RFCOMM_LM_MASTER, RFCOMM_LM_AUTH, RFCOMM_LM_ENCRYPT), (0x01, 0x02, 0x04));
    assert_eq!((RFCOMM_LM_TRUSTED, RFCOMM_LM_RELIABLE, RFCOMM_LM_SECURE, RFCOMM_LM_FIPS),
               (0x08, 0x10, 0x20, 0x40));
    assert_eq!(RFCOMM_CONN_TIMEOUT_MS, 30_000);
    assert_eq!(RFCOMM_DISC_TIMEOUT_MS, 20_000);
    assert_eq!(RFCOMM_AUTH_TIMEOUT_MS, 25_000);
    assert_eq!(RFCOMM_IDLE_TIMEOUT_MS, 2_000);
    assert_eq!(RFCOMM_MAX_DEV, 256);
    assert_eq!(RFCOMM_TTY_MAJOR, 216);
}

#[test]
fn the_payload_widths_are_the_ones_the_abi_defines() {
    assert_eq!((RFCOMM_PN_LEN, RFCOMM_RPN_LEN, RFCOMM_RLS_LEN, RFCOMM_MSC_LEN), (8, 8, 2, 2));
    assert_eq!(RFCOMM_MCC_LEN, 2);
}
