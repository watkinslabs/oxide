//! `NtUserCallOneParam` code coverage, decoding and the adapter query.
use super::*;

/// One `\\.\DISPLAYn` name in the fixed-width buffer the descriptor carries.
fn device_name(text: &str) -> [u16; D3DKMT_NAME_CHARS] {
    let mut name = [0u16; D3DKMT_NAME_CHARS];
    for (slot, unit) in name.iter_mut().zip(text.encode_utf16()) { *slot = unit; }
    name
}

#[test]
fn every_code_the_multiplexer_defines_decodes_to_its_own_arm() {
    for (wire, expected) in CODES.iter().enumerate() {
        assert_eq!(code(wire as u64), Some(*expected), "wire code {wire}");
        assert_eq!(*expected as u32, wire as u32, "discriminant is the wire code");
    }
    assert_eq!(CODES.len(), 16);
    // The three codes the colour family owns keep the numbers it claims.
    assert_eq!(Code::GetSysColor as u32, crate::nt_system_color_raw::GET_SYS_COLOR);
    assert_eq!(Code::GetSysColorBrush as u32, crate::nt_system_color_raw::GET_SYS_COLOR_BRUSH);
    assert_eq!(Code::GetSysColorPen as u32, crate::nt_system_color_raw::GET_SYS_COLOR_PEN);
}

#[test]
fn the_code_argument_is_a_ulong_and_the_high_half_carries_nothing() {
    assert_eq!(code(0xdead_beef_0000_0008), Some(Code::GetSysColorPen));
    assert_eq!(code(0x1234_5678_0000_000f), Some(Code::GetDeskPattern));
}

#[test]
fn an_unknown_code_answers_zero_never_a_status() {
    for wire in [CODES.len() as u64, 32, 0xffff, u64::from(u32::MAX)] { assert_eq!(code(wire), None); }
    assert_eq!(UNHANDLED, 0);
    assert_ne!(UNHANDLED, 0xc000_0002);
}

#[test]
fn the_adapter_query_accepts_only_a_numbered_display_device_name() {
    assert_eq!(display_index(&device_name("\\\\.\\DISPLAY1")), Some(1));
    assert_eq!(display_index(&device_name("\\\\.\\DISPLAY12")), Some(12));
    for name in ["", "\\\\.\\DISPLAY", "\\\\.\\DISPLAY0", "\\\\.\\DISPLAYX", "\\\\.\\display1",
                 "DISPLAY1", "\\\\.\\DISPLAY1X", "\\\\.\\DISPLAY99999999999"] {
        assert_eq!(display_index(&device_name(name)), None, "name {name:?}");
    }
}

#[test]
fn the_adapter_record_places_the_handle_luid_and_source_after_the_name() {
    let record = adapter_record(3, 0x0102_0304_0506_0708);
    assert_eq!(record.len(), D3DKMT_BYTES);
    // The name the caller supplied is left where it is: the query writes only
    // the three answer fields after it.
    assert!(record[..D3DKMT_NAME_CHARS * 2].iter().all(|byte| *byte == 0));
    assert_eq!(&record[D3DKMT_ADAPTER_OFFSET as usize..D3DKMT_ADAPTER_OFFSET as usize + 4], &3u32.to_le_bytes());
    assert_eq!(&record[D3DKMT_LUID_OFFSET as usize..D3DKMT_LUID_OFFSET as usize + 8], &0x0102_0304_0506_0708u64.to_le_bytes());
    // The source id is zero-based where the adapter handle is one-based.
    assert_eq!(&record[D3DKMT_SOURCE_ID_OFFSET as usize..D3DKMT_SOURCE_ID_OFFSET as usize + 4], &2u32.to_le_bytes());
}
