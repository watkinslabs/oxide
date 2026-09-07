use super::{dword, request, run, short, utf16, REGISTRY};
use syscall::nt_native_gdi as abi;

const ENTRY: usize = abi::ENUM_ENTRY_BYTES as usize;

fn enumerate(capacity: u32, output: u64, name: &[u16], charset: u32) -> (u32, u32, Vec<u8>) {
    let request = abi::QueryRequest { count: name.len() as u32, input: if name.is_empty() { 0 } else { 1 },
        first: charset, aux: 0x30000, capacity, output, ..request(abi::QUERY_ENUM_FONTS) };
    let (result, data) = run(&request, name).unwrap();
    (result, dword(&data, 0), data[4..].to_vec())
}

#[test]
fn every_record_is_one_windows_enumeration_entry() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    let (result, bytes, records) = enumerate(64 * ENTRY as u32, 0x10000, &[], 1);
    assert_eq!(result, 1);
    assert!(bytes > 0 && bytes % abi::ENUM_ENTRY_BYTES == 0);
    assert_eq!(records.len(), bytes as usize);
    for entry in records.chunks_exact(ENTRY) {
        // A scalable outline face enumerates as TrueType and never as raster.
        assert_eq!(dword(entry, 0) & 0x0005, 0x0004);
        assert_eq!(String::from_utf16(&entry[32..96].chunks_exact(2)
            .map(|u| u16::from_le_bytes([u[0], u[1]])).take_while(|u| *u != 0).collect::<Vec<_>>()).unwrap(),
            "Liberation Mono");
        // Height, ascent and descent are reported at one fixed enumeration size.
        assert_eq!(dword(entry, 4), dword(entry, 352));
        assert_eq!(dword(entry, 352), dword(entry, 356) + dword(entry, 360));
        assert!(dword(entry, 352) > 0 && dword(entry, 352) <= 64);
        assert_eq!(dword(entry, 416), 2048);
        assert_eq!(entry[31], (entry[352 + 55] & 0xf1) + 1);
        assert_eq!(entry[27], entry[352 + 56]);
        assert_ne!(short(entry, 288), 0xffff);
    }
}

#[test]
fn the_reported_byte_count_survives_a_buffer_that_cannot_hold_it() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    let (_, total, _) = enumerate(64 * ENTRY as u32, 0x10000, &[], 1);
    let (result, bytes, records) = enumerate(ENTRY as u32, 0x10000, &[], 1);
    assert_eq!(bytes, total);
    assert_eq!(records.len(), ENTRY);
    assert_eq!(result, u32::from(total == abi::ENUM_ENTRY_BYTES));
    // A size query writes no record and still reports the full byte count.
    let (result, bytes, records) = enumerate(0, 0, &[], 1);
    assert_eq!((result, bytes, records.len()), (1, total, 0));
}

#[test]
fn a_face_name_selects_that_family_and_an_unknown_name_selects_nothing() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    let (result, named, _) = enumerate(64 * ENTRY as u32, 0x10000, &utf16("liberation mono"), 1);
    assert_eq!(result, 1);
    assert!(named >= 4 * abi::ENUM_ENTRY_BYTES);
    assert_eq!(enumerate(64 * ENTRY as u32, 0x10000, &utf16("No Such Face"), 1), (1, 0, Vec::new()));
}

#[test]
fn a_requested_charset_enumerates_only_that_charset() {
    let _guard = REGISTRY.lock().unwrap_or_else(|poison| poison.into_inner());
    for charset in [0u32, 204, 161] {
        let (_, bytes, records) = enumerate(64 * ENTRY as u32, 0x10000, &[], charset);
        assert_eq!(bytes as usize, records.len());
        for entry in records.chunks_exact(ENTRY) { assert_eq!(u32::from(entry[27]), charset); }
    }
    // A charset the face does not cover enumerates nothing at all.
    assert_eq!(enumerate(64 * ENTRY as u32, 0x10000, &[], 128).1, 0);
}

#[test]
fn the_default_charset_list_leads_with_the_codepage_charset() {
    let list = super::super::charset::list(1);
    assert_eq!(list[0].charset, 0);
    assert!(list.iter().any(|entry| entry.charset == super::super::charset::DEFAULT_CHARSET));
    assert_eq!(list.iter().fold(0u32, |mask, entry| mask | entry.mask), u32::MAX);
    let single = super::super::charset::list(204);
    assert_eq!(single.len(), 1);
    assert_eq!((single[0].charset, single[0].mask, single[0].script), (204, 4, 2));
}
