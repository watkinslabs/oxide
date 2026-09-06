use super::*;

#[test]
fn focus_roundtrip_has_typed_opcode_nonzero_hwnd_and_one_boolean_word() {
    assert_eq!(Opcode::decode(0x108), Ok(Opcode::Focus));
    assert!(Opcode::Focus.from_backend());
    for active in [0u32, 1] {
        let record = Record::new(Opcode::Focus, 7, 42, active.to_le_bytes().to_vec()).unwrap();
        let bytes = record.encode().unwrap();
        assert_eq!(Header::decode(&bytes[..HEADER_LEN]), Ok(record.header));
        assert_eq!(bytes[HEADER_LEN..], active.to_le_bytes());
    }
}

#[test]
fn focus_rejects_raw_x11_values_wrong_lengths_and_missing_hwnd() {
    assert_eq!(Record::new(Opcode::Focus, 1, 42, 2u32.to_le_bytes().to_vec()), Err(Error::Payload));
    assert_eq!(Record::new(Opcode::Focus, 1, 0, 1u32.to_le_bytes().to_vec()), Err(Error::Payload));
    for size in [0, 1, 3, 5, 8] {
        assert_eq!(Record::new(Opcode::Focus, 1, 42, alloc::vec![0; size]), Err(Error::Length));
    }
}
