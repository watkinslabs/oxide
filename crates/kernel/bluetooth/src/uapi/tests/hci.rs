use super::*;

// The handle occupies the low twelve bits and the flags the top four. A
// decoder that kept the flag bits in the handle would look up a link no
// controller has.
#[test]
fn a_handle_and_its_flags_round_trip_through_the_header_word() {
    for handle in [0u16, 1, 0x2a, 0xffe, HCI_HANDLE_MASK] {
        for flags in [ACL_START_NO_FLUSH, ACL_CONT, ACL_START, ACL_ACTIVE_BCAST] {
            let word = acl_pack(handle, flags);
            assert_eq!(acl_unpack(word), (handle, flags), "handle {handle} flags {flags}");
        }
    }
}

#[test]
fn packing_discards_a_handle_that_does_not_fit_rather_than_corrupting_the_flags() {
    let word = acl_pack(0xffff, ACL_START);
    assert_eq!(acl_unpack(word), (HCI_HANDLE_MASK, ACL_START));
}

#[test]
fn the_handle_mask_is_exactly_twelve_bits() {
    assert_eq!(HCI_HANDLE_BITS, 12);
    assert_eq!(HCI_HANDLE_MASK, 0x0fff);
}

// A packet-type prefix collision would route a frame to the wrong decoder.
#[test]
fn no_two_packet_type_prefixes_collide() {
    let types = [HCI_COMMAND_PKT, HCI_ACLDATA_PKT, HCI_SCODATA_PKT, HCI_EVENT_PKT,
        HCI_ISODATA_PKT, HCI_DIAG_PKT, HCI_DRV_PKT, HCI_VENDOR_PKT];
    for (i, t) in types.iter().enumerate() {
        assert!(!types[i + 1..].contains(t), "packet type {t:#04x} appears twice");
    }
}

#[test]
fn the_framed_packet_types_start_at_one_and_are_contiguous() {
    let framed = [HCI_COMMAND_PKT, HCI_ACLDATA_PKT, HCI_SCODATA_PKT, HCI_EVENT_PKT,
        HCI_ISODATA_PKT];
    for (i, t) in framed.iter().enumerate() { assert_eq!(*t, (i + 1) as u8); }
}

// The largest frame must hold the widest header plus the largest payload, or a
// decoder bounded by it would refuse a frame the controller may legally send.
#[test]
fn the_frame_ceiling_holds_the_widest_header_and_the_largest_payload() {
    assert!(HCI_MAX_FRAME_SIZE >= HCI_MAX_ACL_SIZE + HCI_ACL_HDR_SIZE);
    assert!(HCI_MAX_FRAME_SIZE >= HCI_MAX_EVENT_SIZE);
    assert!(HCI_MAX_FRAME_SIZE >= HCI_MAX_SCO_SIZE + HCI_SCO_HDR_SIZE);
}

// A synchronous frame's length field is one byte, so its payload cannot
// exceed what one byte can declare.
#[test]
fn the_single_byte_length_field_bounds_the_synchronous_payload() {
    assert!(HCI_MAX_SCO_SIZE <= u8::MAX as usize);
}

// The event ceiling is a BUFFER allowance, not a declarable length: it exceeds
// what an event's one-byte length field plus its header can express, so a
// buffer sized by it always holds any event a controller can declare. Reading
// it as a declarable maximum would size a decoder's refusal wrongly.
#[test]
fn the_event_ceiling_exceeds_the_largest_declarable_event() {
    assert!(HCI_MAX_EVENT_SIZE > u8::MAX as usize + HCI_EVENT_HDR_SIZE);
}

#[test]
fn the_link_types_are_distinct_and_the_le_one_is_out_of_the_classic_range() {
    let types = [SCO_LINK, ACL_LINK, ESCO_LINK, LE_LINK, CIS_LINK, BIS_LINK, PA_LINK];
    for (i, t) in types.iter().enumerate() {
        assert!(!types[i + 1..].contains(t), "link type {t:#04x} appears twice");
    }
    assert!(LE_LINK > ESCO_LINK);
    assert_eq!(INVALID_LINK, 0xff);
}

#[test]
fn the_bus_types_are_contiguous_from_the_virtual_one() {
    let buses = [HCI_VIRTUAL, HCI_USB, HCI_PCCARD, HCI_UART, HCI_RS232,
        HCI_PCI, HCI_SDIO, HCI_SPI, HCI_I2C, HCI_SMD];
    for (i, b) in buses.iter().enumerate() { assert_eq!(*b, i as u8); }
}

#[test]
fn success_is_the_only_zero_status() {
    assert_eq!(HCI_SUCCESS, 0);
    let errors = [HCI_ERROR_UNKNOWN_CONN_ID, HCI_ERROR_AUTH_FAILURE,
        HCI_ERROR_PIN_OR_KEY_MISSING, HCI_ERROR_MEMORY_EXCEEDED,
        HCI_ERROR_CONNECTION_TIMEOUT, HCI_ERROR_COMMAND_DISALLOWED,
        HCI_ERROR_REJ_LIMITED_RESOURCES, HCI_ERROR_REJ_BAD_ADDR,
        HCI_ERROR_INVALID_PARAMETERS, HCI_ERROR_REMOTE_USER_TERM,
        HCI_ERROR_REMOTE_LOW_RESOURCES, HCI_ERROR_REMOTE_POWER_OFF,
        HCI_ERROR_LOCAL_HOST_TERM, HCI_ERROR_PAIRING_NOT_ALLOWED,
        HCI_ERROR_UNSUPPORTED_REMOTE_FEATURE, HCI_ERROR_INVALID_LL_PARAMS,
        HCI_ERROR_UNSPECIFIED, HCI_ERROR_ADVERTISING_TIMEOUT,
        HCI_ERROR_CANCELLED_BY_HOST];
    for e in errors { assert_ne!(e, HCI_SUCCESS); }
}

// The two packet-type masks partition the synchronous types: a bit in both
// would be selected by a table row meant to exclude it.
#[test]
fn the_two_synchronous_packet_masks_do_not_overlap() {
    assert_eq!(SCO_ESCO_MASK & EDR_ESCO_MASK, 0);
    assert_eq!(SCO_ESCO_MASK, ESCO_HV1 | ESCO_HV2 | ESCO_HV3);
    assert_eq!(EDR_ESCO_MASK, ESCO_2EV3 | ESCO_3EV3 | ESCO_2EV5 | ESCO_3EV5);
}

#[test]
fn each_synchronous_packet_type_is_a_distinct_single_bit() {
    let bits = [ESCO_HV1, ESCO_HV2, ESCO_HV3, ESCO_EV3, ESCO_EV4, ESCO_EV5,
        ESCO_2EV3, ESCO_3EV3, ESCO_2EV5, ESCO_3EV5];
    let mut seen = 0u16;
    for b in bits {
        assert_eq!(b.count_ones(), 1, "{b:#06x} is not a single bit");
        assert_eq!(seen & b, 0, "{b:#06x} collides");
        seen |= b;
    }
}

#[test]
fn the_air_mode_field_fits_inside_its_own_mask() {
    assert_eq!(SCO_AIRMODE_CVSD & !SCO_AIRMODE_MASK, 0);
    assert_eq!(SCO_AIRMODE_TRANSP & !SCO_AIRMODE_MASK, 0);
    assert_ne!(SCO_AIRMODE_CVSD, SCO_AIRMODE_TRANSP);
}

#[test]
fn each_link_mode_bit_is_distinct() {
    let bits = [HCI_LM_MASTER, HCI_LM_AUTH, HCI_LM_ENCRYPT, HCI_LM_TRUSTED,
        HCI_LM_RELIABLE, HCI_LM_SECURE, HCI_LM_FIPS, HCI_LM_ACCEPT];
    let mut seen = 0u16;
    for b in bits { assert_eq!(seen & b, 0, "{b:#06x} collides"); seen |= b; }
}

// A data-type collision would make one inquiry field decode as another.
#[test]
fn no_two_inquiry_data_types_collide() {
    let types = [EIR_FLAGS, EIR_UUID16_SOME, EIR_UUID16_ALL, EIR_UUID32_SOME,
        EIR_UUID32_ALL, EIR_UUID128_SOME, EIR_UUID128_ALL, EIR_NAME_SHORT,
        EIR_NAME_COMPLETE, EIR_TX_POWER, EIR_CLASS_OF_DEV, EIR_SSP_HASH_C192,
        EIR_SSP_RAND_R192, EIR_DEVICE_ID, EIR_SERVICE_DATA, EIR_APPEARANCE,
        EIR_LE_BDADDR, EIR_LE_ROLE, EIR_SSP_HASH_C256, EIR_SSP_RAND_R256,
        EIR_LE_SC_CONFIRM, EIR_LE_SC_RANDOM];
    for (i, t) in types.iter().enumerate() {
        assert!(!types[i + 1..].contains(t), "data type {t:#04x} appears twice");
    }
}

// The no-credit deadline must outlast the command one, or a controller that
// reports a zero allowance would be declared wedged before the command it was
// answering had a chance to time out.
#[test]
fn the_no_credit_deadline_outlasts_the_command_deadline() {
    assert!(HCI_NCMD_TIMEOUT_MS > HCI_CMD_TIMEOUT_MS);
    assert!(HCI_INIT_TIMEOUT_MS > HCI_NCMD_TIMEOUT_MS);
}

#[test]
fn the_command_allowance_is_exactly_one() {
    assert_eq!(HCI_CMD_CREDIT_ONE, 1);
}
