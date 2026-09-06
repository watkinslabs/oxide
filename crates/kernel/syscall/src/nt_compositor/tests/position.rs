use super::*;

fn payload(after: u64, flags: u32, reserved: u32) -> Vec<u8> {
    let mut bytes = after.to_le_bytes().to_vec();
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&reserved.to_le_bytes()); bytes
}

#[test]
fn position_roundtrip_preserves_order_and_activation() {
    assert_eq!(Opcode::decode(7), Ok(Opcode::Position));
    assert!(!Opcode::Position.from_backend());
    for after in [0, 1, u64::MAX, u64::MAX - 1, 42] {
        for flags in [POSITION_ORDER, POSITION_ORDER | POSITION_ACTIVATE] {
            let record = Record::new(Opcode::Position, 7, 9, payload(after, flags, 0)).unwrap();
            let bytes = record.encode().unwrap();
            assert_eq!(Header::decode(&bytes[..HEADER_LEN]), Ok(record.header));
            assert_eq!(u64_at(&bytes[HEADER_LEN..], 0), Ok(after));
            assert_eq!(u32_at(&bytes[HEADER_LEN..], 8), Ok(flags));
        }
    }
    for flags in [0, POSITION_ACTIVATE] {
        assert!(Record::new(Opcode::Position, 7, 9, payload(0, flags, 0)).is_ok());
    }
}

#[test]
fn position_rejects_ambiguous_order_reserved_bits_and_bad_envelopes() {
    for (after, flags, reserved) in [(1, 0, 0), (42, POSITION_ACTIVATE, 0),
        (0, 4, 0), (0, u32::MAX, 0), (0, POSITION_ORDER, 1)] {
        assert_eq!(Record::new(Opcode::Position, 7, 9, payload(after, flags, reserved)), Err(Error::Payload));
    }
    for size in [0, 4, 8, 15, 17, 24] {
        assert_eq!(Record::new(Opcode::Position, 7, 9, alloc::vec![0; size]), Err(Error::Length));
    }
    assert_eq!(Record::new(Opcode::Position, 7, 0, payload(0, 0, 0)), Err(Error::Payload));
    assert_eq!(Record::new(Opcode::Position, 0, 9, payload(0, 0, 0)), Err(Error::Length));
}
