use super::*;

#[test]
fn the_channels_are_contiguous_from_the_raw_one() {
    let all = [HCI_CHANNEL_RAW, HCI_CHANNEL_USER, HCI_CHANNEL_MONITOR,
        HCI_CHANNEL_CONTROL, HCI_CHANNEL_LOGGING];
    for (i, c) in all.iter().enumerate() { assert_eq!(*c, i as u16); }
}

// The no-controller index must be one no real controller can take, or a socket
// asking for "no controller" would attach to one.
#[test]
fn the_no_controller_index_is_outside_any_real_index() {
    assert_eq!(HCI_DEV_NONE, u16::MAX);
}

#[test]
fn the_filter_fields_tile_its_abi_width_without_overlap() {
    assert_eq!(HCI_UFILTER_TYPE_MASK_OFF, 0);
    assert_eq!(HCI_UFILTER_EVENT_MASK_OFF, HCI_UFILTER_TYPE_MASK_OFF + 4);
    assert_eq!(HCI_UFILTER_OPCODE_OFF, HCI_UFILTER_EVENT_MASK_OFF + 8);
    assert_eq!(HCI_UFILTER_LEN, HCI_UFILTER_OPCODE_OFF + 2);
}

#[test]
fn the_address_fields_tile_its_abi_width() {
    assert_eq!(SOCKADDR_HCI_DEV_OFF, 2);
    assert_eq!(SOCKADDR_HCI_CHANNEL_OFF, SOCKADDR_HCI_DEV_OFF + 2);
    assert_eq!(SOCKADDR_HCI_LEN, SOCKADDR_HCI_CHANNEL_OFF + 2);
}

// A field overlapping the next would make one value overwrite another on
// encode and read the wrong bytes on decode.
#[test]
fn the_device_info_fields_do_not_overlap_and_fit_the_struct() {
    let fields: [(usize, usize, &str); 13] = [
        (DEV_INFO_DEV_ID_OFF, 2, "index"),
        (DEV_INFO_NAME_OFF, DEV_INFO_NAME_LEN, "name"),
        (DEV_INFO_BDADDR_OFF, 6, "address"),
        (DEV_INFO_FLAGS_OFF, 4, "flags"),
        (DEV_INFO_TYPE_OFF, 1, "type"),
        (DEV_INFO_FEATURES_OFF, DEV_INFO_FEATURES_LEN, "features"),
        (DEV_INFO_PKT_TYPE_OFF, 4, "packet types"),
        (DEV_INFO_LINK_POLICY_OFF, 4, "link policy"),
        (DEV_INFO_LINK_MODE_OFF, 4, "link mode"),
        (DEV_INFO_ACL_MTU_OFF, 2, "acl mtu"),
        (DEV_INFO_ACL_PKTS_OFF, 2, "acl packets"),
        (DEV_INFO_SCO_MTU_OFF, 2, "sco mtu"),
        (DEV_INFO_SCO_PKTS_OFF, 2, "sco packets"),
    ];
    for (i, (off, len, name)) in fields.iter().enumerate() {
        assert!(off + len <= HCI_DEV_INFO_LEN, "{name} runs past the struct");
        for (off2, len2, name2) in &fields[i + 1..] {
            assert!(off + len <= *off2 || off2 + len2 <= *off,
                "{name} overlaps {name2}");
        }
    }
    assert_eq!(DEV_INFO_STAT_OFF + HCI_DEV_STATS_LEN, HCI_DEV_INFO_LEN);
    assert!(DEV_INFO_SCO_PKTS_OFF + 2 <= DEV_INFO_STAT_OFF);
}

#[test]
fn the_statistics_block_holds_exactly_ten_counters() {
    assert_eq!(HCI_DEV_STATS_LEN, 10 * 4);
}

#[test]
fn the_connection_info_fields_tile_its_width() {
    assert_eq!(CONN_INFO_HANDLE_OFF, 0);
    assert_eq!(CONN_INFO_BDADDR_OFF, 2);
    assert_eq!(CONN_INFO_TYPE_OFF, CONN_INFO_BDADDR_OFF + 6);
    assert_eq!(CONN_INFO_OUT_OFF, CONN_INFO_TYPE_OFF + 1);
    assert_eq!(CONN_INFO_STATE_OFF, CONN_INFO_OUT_OFF + 1);
    assert_eq!(CONN_INFO_LINK_MODE_OFF, CONN_INFO_STATE_OFF + 2);
    assert_eq!(HCI_CONN_INFO_LEN, CONN_INFO_LINK_MODE_OFF + 4);
}

#[test]
fn no_two_device_ioctls_collide() {
    let all = [HCIDEVUP, HCIDEVDOWN, HCIDEVRESET, HCIDEVRESTAT, HCIGETDEVLIST,
        HCIGETDEVINFO, HCIGETCONNLIST, HCIGETCONNINFO, HCIGETAUTHINFO, HCISETRAW,
        HCISETSCAN, HCISETAUTH, HCISETENCRYPT, HCISETPTYPE, HCISETLINKPOL,
        HCISETLINKMODE, HCISETACLMTU, HCISETSCOMTU, HCIBLOCKADDR, HCIUNBLOCKADDR,
        HCIINQUIRY];
    for (i, c) in all.iter().enumerate() {
        assert!(!all[i + 1..].contains(c), "ioctl {c} appears twice");
    }
}

#[test]
fn the_device_state_flags_are_distinct_bit_positions() {
    let all = [HCI_UP, HCI_INIT, HCI_RUNNING, HCI_PSCAN, HCI_ISCAN, HCI_AUTH,
        HCI_ENCRYPT, HCI_INQUIRY, HCI_RAW, HCI_RESET];
    for (i, b) in all.iter().enumerate() {
        assert!(*b < 32, "flag {b} does not fit the reported word");
        assert!(!all[i + 1..].contains(b), "flag {b} appears twice");
    }
}

#[test]
fn the_two_ancillary_markers_are_independent_bits() {
    assert_eq!(HCI_CMSG_DIR & HCI_CMSG_TSTAMP, 0);
}

#[test]
fn the_three_option_numbers_are_distinct() {
    let all = [HCI_DATA_DIR, HCI_FILTER, HCI_TIME_STAMP];
    for (i, o) in all.iter().enumerate() {
        assert!(!all[i + 1..].contains(o), "option {o} appears twice");
    }
}
