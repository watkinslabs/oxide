use super::*;
fn params() -> Params { Params { procedure: 0x140012340, hwnd: 42, message: 0x30,
    wparam: 0xa0040, lparam: 7, ansi: true, ansi_dst: false, mapping: MAP_SEND, dpi_context: 0 } }

#[test]
fn canonical_procedure_and_message_fill_exact_native_layout() {
    let bytes = encode(params());
    for offset in [0, 56, 64] { assert_eq!(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()), params().procedure); }
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 42);
    assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 0x30);
    assert_eq!(bytes[40], 1); assert_eq!(bytes[44], 0); assert_eq!(bytes[48], MAP_SEND as u8);
}

#[test]
fn readiness_is_written_last_and_fault_leaves_hwnd_zero() {
    for failure in 0..5 {
        let mut bytes = [0u8; BYTES]; let mut calls = 0;
        let success = publish(0x10000, params(), |address, input| {
            let call = calls; calls += 1;
            if call == failure { return false; }
            let start = (address - 0x10000) as usize;
            bytes[start..start + input.len()].copy_from_slice(input); true
        });
        assert_eq!(success, failure == 4);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), if success { 42 } else { 0 });
    }
}

#[test]
fn invalid_pointer_never_calls_transfer() {
    for pointer in [0, u64::MAX - 32] { assert!(!publish(pointer, params(), |_, _| panic!("invalid range reached copy"))); }
}
