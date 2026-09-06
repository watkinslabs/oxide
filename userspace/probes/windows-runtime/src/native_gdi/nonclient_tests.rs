use syscall::nt_native_gdi as abi;
fn profile(size: u32, height: i32) -> Vec<u16> {
    let mut bytes = [0u8; 504];
    bytes[..4].copy_from_slice(&size.to_le_bytes());
    for offset in [24, 124, 224, 316, 408] {
        bytes[offset..offset + 4].copy_from_slice(&height.to_le_bytes());
        bytes[offset + 16..offset + 20].copy_from_slice(&400i32.to_le_bytes());
        bytes[offset + 28..offset + 32].copy_from_slice(&[65, 0, 66, 0]);
    }
    bytes.chunks_exact(2).map(|b| u16::from_le_bytes(b.try_into().unwrap())).collect()
}
fn integer(bytes: &[u8], offset: usize) -> i32 { i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }
#[test]
fn system_metrics_return_real_normalized_font_height_without_user_output() {
    super::native::prepare_fonts().unwrap();
    let input = profile(504, -30);
    let normalized = super::nonclient::normalize(&input, 504).unwrap();
    let font = super::native::selected_font(-30, 400, 0).unwrap();
    let bytes = super::native::selected_bytes(400, 0).unwrap();
    for (index, offset, extra) in [(4,20,1), (15,220,1), (31,20,0), (51,120,1), (53,120,0), (55,220,0), (57,20,6)] {
        let req = abi::QueryRequest { version: abi::VERSION, size: 80, dc: 0, kind: abi::QUERY_SYSTEM_METRIC,
            flags: 0, height: 0, width: 0, weight: 0, italic: 0, first: index, count: 252, input: 0x1000,
            output: 0, table: 0, offset: 0, capacity: 0, reserved: 0 };
        assert!(req.valid());
        let (result, output) = super::query::execute(&font, bytes, &req, &input).unwrap();
        assert_eq!(result, (integer(&normalized, offset) + extra) as u32);
        assert!(result > 30);
        assert!(output.is_empty());
        let out = abi::QueryOutput { result, length: 0, data: 0, reserved: 0 };
        assert!(req.accepts(&out));
        assert!(!req.accepts(&abi::QueryOutput { result: 0, ..out }));
        assert!(!req.accepts(&abi::QueryOutput { length: 4, data: 0x4000, ..out }));
        assert!(!abi::QueryRequest { first: 2, ..req }.valid());
        assert!(!abi::QueryRequest { count: 251, ..req }.valid());
        assert!(!abi::QueryRequest { capacity: 504, ..req }.valid());
        assert!(!abi::QueryRequest { output: 0x4000, ..req }.valid());
        assert!(super::query::execute(&font, bytes, &req, &input[..251]).is_none());
    }
    assert!(super::nonclient::system_metric(&profile(504, i32::MIN), 31).is_none());
    assert!(super::nonclient::system_metric(&input, 2).is_none());
}
#[test]
fn nonclient_heights_use_real_native_font_and_legacy_copy_bound() {
    super::native::prepare_fonts().unwrap();
    let font = super::native::selected_font(-30, 400, 0).unwrap();
    let tm = font.text_metrics_w(400, 0).unwrap();
    for size in [500, 504] {
        let input = profile(size, -30);
        let output = super::nonclient::normalize(&input, size).unwrap();
        assert_eq!(output.len(), size as usize);
        assert_eq!(integer(&output, 0), size as i32);
        for offset in [20, 120] { assert_eq!(integer(&output, offset), 2 + integer(&tm, 0)); }
        assert_eq!(integer(&output, 220), 2 + integer(&tm, 0) + integer(&tm, 16));
        assert!(integer(&output, 220) > 20);
        for (offset, expected) in [(4, 1), (8, 8), (12, 8), (16, 8)] { assert_eq!(integer(&output, offset), expected); }
        let raw: Vec<u8> = input.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(&output[316..408], &raw[316..408]);
        assert_eq!(&output[408..500], &raw[408..500]);
    }
}
#[test]
fn nonclient_callback_copy_policy_requires_exact_complete_profile_output() {
    let req = abi::QueryRequest { version: abi::VERSION, size: 80, dc: 0, kind: abi::QUERY_NONCLIENT,
        flags: 0, height: 0, width: 0, weight: 0, italic: 0, first: 0, count: 252, input: 0x1000,
        output: 0x2000, table: 0, offset: 0, capacity: 500, reserved: 0 };
    assert!(req.valid());
    let out = abi::QueryOutput { result: 1, length: 500, data: 0x3000, reserved: 0 };
    assert!(req.accepts(&out));
    assert!(!req.accepts(&abi::QueryOutput { length: 504, ..out }));
    assert!(!abi::QueryRequest { kind: abi::QUERY_CHARSET, ..req }.valid());
    assert!(!abi::QueryRequest { count: 250, ..req }.valid());
    assert!(super::nonclient::normalize(&profile(504, -11), 500).is_none());
    assert!(super::nonclient::normalize(&profile(500, -11)[..250], 500).is_none());
    assert!(super::nonclient::normalize(&profile(500, i32::MIN), 500).is_none());
}
