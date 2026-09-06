use syscall::nt_native_gdi as abi;
use super::{native, query, resource};
fn request(kind: u32) -> abi::QueryRequest {
    abi::QueryRequest { version: abi::VERSION, size: 80, dc: 1, kind, flags: 0,
        height: 16, width: 0, weight: 400, italic: 0, first: 0, count: 0, input: 0,
        output: 0x10000, table: 0, offset: 0, capacity: 0, reserved: 0 }
}
fn run(request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    native::prepare_fonts().unwrap();
    let font = native::selected_font_with_width(request.height, request.width, request.weight, request.italic)?;
    query::execute(&font, native::selected_bytes(request.weight, request.italic)?, request, input)
}
fn word(bytes: &[u8], offset: usize) -> u32 { u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }

#[test]
fn charset_reads_real_os2_signature_all_selected_resources() {
    for (weight, italic) in [(400, 0), (700, 0), (400, 1), (700, 1)] {
        let req = abi::QueryRequest { weight, italic, flags: u32::MAX, ..request(abi::QUERY_CHARSET) };
        let (charset, signature) = run(&req, &[]).unwrap();
        assert_eq!(charset, 0); assert_eq!(signature.len(), 24);
        let bytes = native::selected_bytes(weight, italic).unwrap();
        let os2 = native::font_height::table(bytes, b"OS/2").unwrap();
        for (i, offset) in [42, 46, 50, 54, 78, 82].into_iter().enumerate() {
            assert_eq!(word(&signature, i * 4), u32::from_be_bytes(os2[offset..offset + 4].try_into().unwrap()));
        }
        assert_ne!(word(&signature, 0), 0); assert_ne!(word(&signature, 16) & 1, 0);
        assert_eq!(run(&abi::QueryRequest { output: 0, ..req }, &[]), Some((0, Vec::new())));
    }
    assert!(resource::signature(&[0; 40]).is_none());
}

#[test]
fn font_table_data_size_offset_endianness_and_failure_are_real() {
    let req = abi::QueryRequest { table: u32::from_le_bytes(*b"head"), ..request(abi::QUERY_DATA) };
    let (size, empty) = run(&req, &[]).unwrap();
    assert_eq!(size, 54); assert!(empty.is_empty());
    assert_eq!(run(&abi::QueryRequest { offset: u32::MAX, output: 0, ..req }, &[]).unwrap().0, size);
    let (_, data) = run(&abi::QueryRequest { offset: 12, capacity: 4, ..req }, &[]).unwrap();
    assert_eq!(data, 0x5f0f3cf5u32.to_be_bytes());
    assert!(run(&abi::QueryRequest { offset: 53, capacity: 2, ..req }, &[]).is_none());
    assert!(run(&abi::QueryRequest { table: u32::from_le_bytes(*b"NOPE"), ..req }, &[]).is_none());
    assert!(run(&abi::QueryRequest { table: u32::from_be_bytes(*b"head"), ..req }, &[]).is_none());
    let full = run(&abi::QueryRequest { table: 0, output: 0, ..req }, &[]).unwrap().0;
    assert_eq!(full as usize, native::selected_bytes(400, 0).unwrap().len());
}

#[test]
fn glyph_query_wchar_units_and_abc_use_identical_font_geometry() {
    let text = [65, 66, 0xd83d, 0xde00, 0xffff];
    let req = abi::QueryRequest { input: 1, count: 5, flags: 1, ..request(abi::QUERY_GLYPHS) };
    let (count, data) = run(&req, &text).unwrap();
    assert_eq!(count, 5);
    let glyphs: Vec<u16> = data.chunks_exact(2).map(|b| u16::from_le_bytes(b.try_into().unwrap())).collect();
    assert_ne!(glyphs[0], 65); assert!(glyphs[0] > 0); assert_ne!(glyphs[0], glyphs[1]);
    assert_eq!(&glyphs[2..], &[65535; 3]);
    let req = abi::QueryRequest { input: 1, count: 2, flags: abi::ABC_INTEGER | abi::ABC_INDICES, ..request(abi::QUERY_ABC) };
    for width in [0, 7, 14] {
        let req = abi::QueryRequest { width, ..req };
        let (result, abc) = run(&req, &glyphs[..2]).unwrap(); assert_eq!(result, 1);
        let font = native::selected_font_with_width(16, width, 400, 0).unwrap();
        for (i, glyph) in glyphs[..2].iter().enumerate() {
            let actual = font.glyph_abc(*glyph).unwrap();
            assert!(actual[1] > 0); assert!(actual.iter().sum::<i32>() > 1);
            for j in 0..3 { assert_eq!(word(&abc, i * 12 + j * 4) as i32, actual[j]); }
        }
        let unicode = run(&abi::QueryRequest { flags: abi::ABC_INTEGER, ..req }, &text[..2]).unwrap();
        assert_eq!(unicode.1, abc);
        let floats = run(&abi::QueryRequest { flags: abi::ABC_INDICES, ..req }, &glyphs[..2]).unwrap().1;
        for (a, b) in abc.chunks_exact(4).zip(floats.chunks_exact(4)) {
            assert_eq!(i32::from_le_bytes(a.try_into().unwrap()) as f32, f32::from_le_bytes(b.try_into().unwrap()));
        }
    }
}

#[test]
fn outline_full_record_real_names_and_short_prefix() {
    let req = request(abi::QUERY_OUTLINE);
    let size = run(&abi::QueryRequest { output: 0, ..req }, &[]).unwrap().0;
    assert!(size > 232);
    let (result, data) = run(&abi::QueryRequest { capacity: size, ..req }, &[]).unwrap();
    assert_eq!(result, size); assert_eq!(word(&data, 0), size); assert_eq!(word(&data, 96), 2048);
    assert!(word(&data, 100) > 0); assert!((word(&data, 104) as i32) < 0);
    assert!(data[65..75].iter().any(|v| *v != 0));
    for offset in [200, 208, 216, 224] {
        let start = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
        assert!(start >= 232 && start < data.len());
        let name: Vec<u16> = data[start..].chunks_exact(2).map(|b| u16::from_le_bytes(b.try_into().unwrap())).take_while(|v| *v != 0).collect();
        assert!(!name.is_empty());
        if offset == 200 { assert_eq!(String::from_utf16(&name).unwrap(), "Liberation Mono"); }
    }
    let (result, prefix) = run(&abi::QueryRequest { capacity: 216, ..req }, &[]).unwrap();
    assert_eq!(result, 216); assert_eq!(prefix, data[..216]);
}

#[test]
fn query_wire_and_copyout_bounds_reject_untrusted_lengths_before_writes() {
    assert_eq!(std::mem::size_of::<abi::QueryRequest>(), 80);
    assert_eq!(std::mem::size_of::<abi::QueryOutput>(), 24);
    assert_eq!(std::mem::offset_of!(abi::QueryRequest, input), 48);
    let req = request(abi::QUERY_CHARSET);
    let out = abi::QueryOutput { result: 0, length: 24, data: 0x20000, reserved: 0 };
    assert!(req.accepts(&out));
    assert!(!req.accepts(&abi::QueryOutput { length: 23, ..out }));
    assert!(!req.accepts(&abi::QueryOutput { data: u64::MAX - 10, ..out }));
    assert!(!req.accepts(&abi::QueryOutput { reserved: 1, ..out }));
    assert_eq!(request(abi::QUERY_CHARSET).failure(), 1);
    assert_eq!(request(abi::QUERY_DATA).failure(), u32::MAX as u64);
    assert_eq!(request(abi::QUERY_GLYPHS).failure(), u32::MAX as u64);
    for bad in [abi::QueryRequest { count: abi::MAX_UNITS + 1, ..req }, abi::QueryRequest { output: u64::MAX, ..req },
        abi::QueryRequest { height: i32::MIN, ..req }, abi::QueryRequest { reserved: 1, ..req }] { assert!(!bad.valid()); }
}
