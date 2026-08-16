use super::*;
use bluetooth::uapi::hci::{HCI_COMMAND_PKT, HCI_MAX_FRAME_SIZE};

#[test]
fn a_write_shorter_than_a_type_and_a_byte_is_refused() {
    assert_eq!(parse_write(&[], true), Err(Errno::Einval));
    assert_eq!(parse_write(&[HCI_EVENT_PKT], true), Err(Errno::Einval));
}

#[test]
fn a_write_larger_than_the_largest_frame_is_refused() {
    let big = alloc::vec![HCI_ACLDATA_PKT; HCI_MAX_FRAME_SIZE + 1];
    assert_eq!(parse_write(&big, true), Err(Errno::Einval));
    let ok = alloc::vec![HCI_ACLDATA_PKT; HCI_MAX_FRAME_SIZE];
    assert!(parse_write(&ok, true).is_ok());
}

// Only traffic the controller reports to the host is accepted. A command
// packet travels the other way and has no meaning arriving here.
#[test]
fn the_four_controller_to_host_types_are_accepted_and_others_are_not() {
    for t in [HCI_EVENT_PKT, HCI_ACLDATA_PKT, HCI_SCODATA_PKT, HCI_ISODATA_PKT] {
        assert!(matches!(parse_write(&[t, 0x01], true), Ok(WriteAction::Frame(_))));
    }
    assert_eq!(parse_write(&[HCI_COMMAND_PKT, 0x01], true), Err(Errno::Einval));
    assert_eq!(parse_write(&[0x77, 0x01], true), Err(Errno::Einval));
}

// A frame handed up keeps its prefix: the stack's own decoder reads the type
// from it, and stripping it here would make the driver decide the framing.
#[test]
fn an_accepted_frame_keeps_its_packet_type_prefix() {
    let bytes = [HCI_EVENT_PKT, 0x0e, 0x01, 0x00];
    assert_eq!(parse_write(&bytes, true), Ok(WriteAction::Frame(bytes.to_vec())));
}

// A frame arriving before a controller exists has nowhere to go.
#[test]
fn a_frame_before_any_controller_exists_is_refused() {
    assert_eq!(parse_write(&[HCI_EVENT_PKT, 0x0e], false), Err(Errno::Enodev));
}

#[test]
fn a_creation_request_is_exactly_one_opcode_byte() {
    assert_eq!(parse_write(&[HCI_VENDOR_PKT, 0x00], false),
        Ok(WriteAction::Create(CreateFlags { external_config: false, raw_device: false, opcode: 0 })));
    // Trailing bytes mean the writer meant something else.
    assert_eq!(parse_write(&[HCI_VENDOR_PKT, 0x00, 0x00], false), Err(Errno::Einval));
}

// A second creation would leave the first controller unreachable through a
// description that now names another.
#[test]
fn a_second_creation_on_one_description_is_refused() {
    assert_eq!(parse_write(&[HCI_VENDOR_PKT, 0x00], true), Err(Errno::Ebadf));
}

// A reserved bit is a property that does not exist. Ignoring it would leave the
// caller believing a request was honoured.
#[test]
fn every_reserved_opcode_bit_is_refused_rather_than_ignored() {
    for bit in 2..=5u8 {
        assert_eq!(parse_create_opcode(1 << bit), Err(Errno::Einval), "bit {bit}");
        assert_eq!(parse_write(&[HCI_VENDOR_PKT, 1 << bit], false), Err(Errno::Einval));
    }
}

#[test]
fn the_two_defined_property_bits_are_read_independently() {
    let plain = parse_create_opcode(0x00).unwrap();
    assert!(!plain.external_config && !plain.raw_device);
    let ext = parse_create_opcode(CREATE_EXTERNAL_CONFIG).unwrap();
    assert!(ext.external_config && !ext.raw_device);
    let raw = parse_create_opcode(CREATE_RAW_DEVICE).unwrap();
    assert!(!raw.external_config && raw.raw_device);
    let both = parse_create_opcode(CREATE_EXTERNAL_CONFIG | CREATE_RAW_DEVICE).unwrap();
    assert!(both.external_config && both.raw_device);
}

// Bits 0 and 1 are neither reserved nor defined as properties here; they must
// still be accepted, because refusing them would reject a request the protocol
// permits.
#[test]
fn the_low_two_opcode_bits_are_accepted() {
    assert!(parse_create_opcode(0x01).is_ok());
    assert!(parse_create_opcode(0x02).is_ok());
    assert!(parse_create_opcode(0x03).is_ok());
}

// The acknowledgement tells the process which controller it now owns.
#[test]
fn the_creation_acknowledgement_echoes_the_opcode_and_names_the_index() {
    let flags = parse_create_opcode(CREATE_RAW_DEVICE).unwrap();
    assert_eq!(creation_ack(flags, 0), alloc::vec![HCI_VENDOR_PKT, CREATE_ACK_MARK, 0x80, 0x00, 0x00]);
    assert_eq!(creation_ack(flags, 258), alloc::vec![HCI_VENDOR_PKT, CREATE_ACK_MARK, 0x80, 0x02, 0x01]);
}

// The acknowledgement is itself a vendor frame, so a process reading its own
// device back sees a well-formed packet type.
#[test]
fn the_acknowledgement_is_prefixed_as_a_vendor_packet() {
    let ack = creation_ack(CreateFlags::default(), 3);
    assert_eq!(ack[0], HCI_VENDOR_PKT);
    assert_eq!(ack.len(), 5);
}
