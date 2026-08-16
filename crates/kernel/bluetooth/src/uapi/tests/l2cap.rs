//! Constant contracts: the widths the layouts imply, the identifier ranges,
//! and the enumerations that must stay disjoint.

use super::*;

#[test]
fn the_header_widths_match_the_layouts_they_describe() {
    assert_eq!(HDR_SIZE, LEN_SIZE + 2);
    assert_eq!(ENH_HDR_SIZE, HDR_SIZE + ENH_CTRL_SIZE);
    assert_eq!(EXT_HDR_SIZE, HDR_SIZE + EXT_CTRL_SIZE);
    assert_eq!(CMD_HDR_SIZE, 4);
    assert_eq!(SDULEN_SIZE, 2);
    assert_eq!(PSMLEN_SIZE, 2);
    assert_eq!(FCS_SIZE, 2);
}

#[test]
fn the_option_widths_match_their_field_lists() {
    // mode, window, retry count, then three 16-bit timers and sizes.
    assert_eq!(CONF_RFC_LEN, 3 + 3 * 2);
    // two bytes, a 16-bit size, then three 32-bit figures.
    assert_eq!(CONF_EFS_LEN, 2 + 2 + 3 * 4);
    assert_eq!(CONF_MTU_LEN, 2);
    assert_eq!(CONF_EWS_LEN, 2);
    assert_eq!(CONF_FCS_LEN, 1);
    assert!(CONF_EFS_LEN <= CONF_MAX_SIZE);
    assert!(CONF_QOS_LEN <= CONF_MAX_SIZE);
}

#[test]
fn the_command_payload_widths_match_their_field_lists() {
    assert_eq!(CONN_REQ_LEN, 4);
    assert_eq!(CONN_RSP_LEN, 8);
    assert_eq!(LE_CONN_REQ_LEN, 10);
    assert_eq!(LE_CONN_RSP_LEN, 10);
    assert_eq!(LE_CREDITS_LEN, 4);
    assert_eq!(ECRED_CONN_REQ_HDR_LEN, 8);
    assert_eq!(ECRED_CONN_RSP_HDR_LEN, 8);
    assert_eq!(ECRED_RECONF_REQ_HDR_LEN, 4);
    assert_eq!(CID_WIDTH, 2);
}

#[test]
fn the_socket_layouts_have_the_widths_their_fields_and_padding_imply() {
    // family, multiplexer, address, identifier, address type, aligned.
    assert_eq!(SOCKADDR_L2_LEN, 14);
    assert_eq!(SOCKADDR_L2_BDADDR_OFF, 4);
    assert_eq!(SOCKADDR_L2_CID_OFF, 10);
    assert_eq!(SOCKADDR_L2_BDADDR_TYPE_OFF, 12);
    // three 16-bit values, three bytes, a pad byte, a 16-bit window.
    assert_eq!(L2CAP_OPTIONS_LEN, 3 * 2 + 3 + 1 + 2);
    // a handle and a three-byte class, aligned.
    assert_eq!(L2CAP_CONNINFO_LEN, 2 + DEV_CLASS_LEN + 1);
}

#[test]
fn the_fixed_identifiers_sit_below_the_dynamic_range() {
    for cid in [CID_SIGNALING, CID_CONN_LESS, CID_ATT, CID_LE_SIGNALING, CID_SMP, CID_SMP_BREDR] {
        assert!(cid < CID_DYN_START, "fixed identifier {cid:#x} overlaps the dynamic range");
    }
    assert!(CID_LE_DYN_END < CID_DYN_END);
    assert!(CID_DYN_START <= CID_LE_DYN_END);
}

#[test]
fn the_fixed_channel_mask_bits_are_distinct() {
    let bits = [FC_SIG_BREDR, FC_CONNLESS, FC_ATT, FC_SIG_LE, FC_SMP_LE, FC_SMP_BREDR];
    let mut or = 0u8;
    for b in bits { assert_eq!(or & b, 0, "bit {b:#x} repeats"); or |= b; }
}

#[test]
fn the_feature_mask_bits_are_distinct() {
    let bits = [FEAT_FLOWCTL, FEAT_RETRANS, FEAT_BIDIR_QOS, FEAT_ERTM, FEAT_STREAMING,
                FEAT_FCS, FEAT_EXT_FLOW, FEAT_FIXED_CHAN, FEAT_EXT_WINDOW, FEAT_UCD];
    let mut or = 0u32;
    for b in bits { assert_eq!(or & b, 0, "bit {b:#x} repeats"); or |= b; }
    assert_eq!(FEAT_MASK_LEN, 4);
}

#[test]
fn the_internal_modes_can_never_be_mistaken_for_an_on_air_one() {
    for on_air in [MODE_BASIC, MODE_RETRANS, MODE_FLOWCTL, MODE_ERTM, MODE_STREAMING] {
        assert!(on_air < MODE_LE_FLOWCTL, "mode {on_air:#x} collides with the internal range");
    }
    assert_ne!(MODE_LE_FLOWCTL, MODE_EXT_FLOWCTL);
}

#[test]
fn the_control_field_masks_do_not_overlap_within_a_frame_kind() {
    // Information frame: segmentation, sequence, acknowledgement, final.
    assert_eq!(CTRL_SAR & CTRL_TXSEQ, 0);
    assert_eq!(CTRL_SAR & CTRL_REQSEQ, 0);
    assert_eq!(CTRL_TXSEQ & CTRL_REQSEQ, 0);
    assert_eq!(CTRL_TXSEQ & CTRL_FRAME_TYPE, 0);
    // Supervisory frame: function, poll, acknowledgement.
    assert_eq!(CTRL_SUPERVISE & CTRL_POLL, 0);
    assert_eq!(CTRL_SUPERVISE & CTRL_REQSEQ, 0);
    assert_eq!(CTRL_POLL & CTRL_REQSEQ, 0);
    // The extended field, likewise.
    assert_eq!(EXT_CTRL_TXSEQ & EXT_CTRL_REQSEQ, 0);
    assert_eq!(EXT_CTRL_SAR & EXT_CTRL_REQSEQ, 0);
    assert_eq!(EXT_CTRL_POLL & EXT_CTRL_SUPERVISE, 0);
    assert_eq!(EXT_CTRL_FINAL & EXT_CTRL_FRAME_TYPE, 0);
}

#[test]
fn each_mask_and_its_shift_agree() {
    assert_eq!(CTRL_SAR >> CTRL_SAR_SHIFT, 0x3);
    assert_eq!(CTRL_REQSEQ >> CTRL_REQSEQ_SHIFT, 0x3f);
    assert_eq!(CTRL_TXSEQ >> CTRL_TXSEQ_SHIFT, 0x3f);
    assert_eq!(CTRL_SUPERVISE >> CTRL_SUPER_SHIFT, 0x3);
    assert_eq!(CTRL_POLL >> CTRL_POLL_SHIFT, 1);
    assert_eq!(CTRL_FINAL >> CTRL_FINAL_SHIFT, 1);
    assert_eq!(EXT_CTRL_TXSEQ >> EXT_CTRL_TXSEQ_SHIFT, 0x3fff);
    assert_eq!(EXT_CTRL_REQSEQ >> EXT_CTRL_REQSEQ_SHIFT, 0x3fff);
    assert_eq!(EXT_CTRL_SAR >> EXT_CTRL_SAR_SHIFT, 0x3);
    assert_eq!(EXT_CTRL_POLL >> EXT_CTRL_POLL_SHIFT, 1);
    assert_eq!(EXT_CTRL_FINAL >> EXT_CTRL_FINAL_SHIFT, 1);
}

#[test]
fn the_window_defaults_fit_the_field_that_carries_them() {
    assert_eq!(DEFAULT_TX_WINDOW as u16, (CTRL_TXSEQ >> CTRL_TXSEQ_SHIFT) as u16);
    assert_eq!(DEFAULT_EXT_WINDOW as u32, EXT_CTRL_TXSEQ >> EXT_CTRL_TXSEQ_SHIFT);
}

#[test]
fn the_two_connect_result_enumerations_are_read_separately() {
    // The same number means different things on the two transports, which is
    // why they are two enumerations rather than one.
    assert_eq!(CR_SEC_BLOCK, 0x0003);
    assert_ne!(CR_LE_AUTHENTICATION, CR_SEC_BLOCK);
    assert_eq!(CR_INVALID_SCID, 0x0006);
    assert_eq!(CR_LE_INVALID_SCID, 0x0009);
    assert_eq!(CR_SUCCESS, CR_LE_SUCCESS);
    assert_eq!(CR_BAD_PSM, CR_LE_BAD_PSM);
    assert_eq!(CR_NO_MEM, CR_LE_NO_MEM);
}

#[test]
fn the_multiplexer_ranges_are_ordered_and_the_known_ones_are_well_formed() {
    assert!(PSM_DYN_START <= PSM_AUTO_END);
    assert!(PSM_AUTO_END < PSM_DYN_END);
    assert!(PSM_LE_DYN_START <= PSM_LE_DYN_END);
    for psm in [PSM_SDP, PSM_RFCOMM, PSM_3DSP, PSM_IPSP] {
        assert_eq!(psm & PSM_BREDR_MASK, PSM_BREDR_VALID, "{psm:#x} is not a well-formed multiplexer");
        assert!(psm < PSM_DYN_START);
    }
}

#[test]
fn the_signalling_command_codes_are_distinct() {
    let codes = [COMMAND_REJ, CONN_REQ, CONN_RSP, CONF_REQ, CONF_RSP, DISCONN_REQ, DISCONN_RSP,
                 ECHO_REQ, ECHO_RSP, INFO_REQ, INFO_RSP, CONN_PARAM_UPDATE_REQ, CONN_PARAM_UPDATE_RSP,
                 LE_CONN_REQ, LE_CONN_RSP, LE_CREDITS, ECRED_CONN_REQ, ECRED_CONN_RSP,
                 ECRED_RECONF_REQ, ECRED_RECONF_RSP];
    for (i, a) in codes.iter().enumerate() {
        for b in &codes[i + 1..] { assert_ne!(a, b, "code {a:#x} repeats"); }
    }
}

#[test]
fn the_hint_bit_and_the_type_mask_partition_the_option_type_byte() {
    assert_eq!(CONF_HINT & CONF_MASK, 0);
    assert_eq!(CONF_HINT | CONF_MASK, 0xff);
    for t in [CONF_MTU, CONF_FLUSH_TO, CONF_QOS, CONF_RFC, CONF_FCS, CONF_EFS, CONF_EWS] {
        assert_eq!(t & CONF_HINT, 0, "option type {t:#x} collides with the hint bit");
    }
}

#[test]
fn the_credit_ceiling_is_the_whole_range_the_field_can_express() {
    assert_eq!(LE_MAX_CREDITS, u16::MAX);
    assert!(ECRED_MIN_MTU >= LE_MIN_MTU);
    assert!(ECRED_MIN_MPS >= LE_MIN_MTU);
    assert_eq!(ECRED_MAX_CID, 5);
}

#[test]
fn the_key_size_floors_are_ordered() {
    assert!(MIN_ENC_KEY_SIZE < FIPS_ENC_KEY_SIZE);
    assert_eq!(FIPS_ENC_KEY_SIZE, 16);
}
