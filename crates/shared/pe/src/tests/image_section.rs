//! Image-shaped view layout and the record a section query returns.

use super::super::*;
use super::{image, OPT, SEC};
use alloc::vec::Vec;
use std::{eprintln, format, path::PathBuf, string::{String, ToString}};

const SEC2: usize = SEC + 40;

/// Two-section image: an executable `.text` whose virtual size exceeds its raw
/// size, and a writable `.data` that supplies no file bytes at all.
fn two_section_image() -> Vec<u8> {
    let mut b = image();
    b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    b[OPT + 56..OPT + 60].copy_from_slice(&0x4000u32.to_le_bytes());
    // .text keeps 0x200 file bytes but claims 0x1800 of address space.
    b[SEC + 8..SEC + 12].copy_from_slice(&0x1800u32.to_le_bytes());
    b[SEC2..SEC2 + 8].copy_from_slice(b".data\0\0\0");
    b[SEC2 + 8..SEC2 + 12].copy_from_slice(&0x800u32.to_le_bytes());
    b[SEC2 + 12..SEC2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    b[SEC2 + 16..SEC2 + 20].copy_from_slice(&0u32.to_le_bytes());
    b[SEC2 + 20..SEC2 + 24].copy_from_slice(&0u32.to_le_bytes());
    b[SEC2 + 36..SEC2 + 40].copy_from_slice(&(SectionFlags::MEM_READ | SectionFlags::MEM_WRITE).to_le_bytes());
    b
}

#[test]
fn every_section_is_placed_at_its_own_relative_address_with_its_own_protection() {
    let b = two_section_image();
    let parsed = parse(&b).unwrap();
    let spans = view_layout(&parsed).unwrap();
    assert_eq!(spans.len(), 3, "headers plus one span per section");
    assert_eq!(spans[0].rva, 0);
    assert_eq!(spans[0].prot, SpanProt { read: true, write: false, exec: false });
    assert_eq!(spans[1].rva, 0x1000);
    assert_eq!(spans[1].size, 0x2000, "the span rounds to the section alignment");
    assert_eq!(spans[1].prot, SpanProt { read: true, write: false, exec: true });
    assert_eq!(spans[2].rva, 0x3000);
    assert_eq!(spans[2].size, 0x1000);
    assert_eq!(spans[2].prot, SpanProt { read: true, write: true, exec: false });
    // A flat data view would put .data's bytes at its file offset, not 0x3000.
    assert!(spans.iter().all(|span| span.rva != span.file_offset || span.rva == 0));
}

#[test]
fn a_section_tail_past_its_file_bytes_is_zero_filled_address_space() {
    let b = two_section_image();
    let parsed = parse(&b).unwrap();
    let spans = view_layout(&parsed).unwrap();
    assert_eq!(spans[1].file_bytes, 0x200);
    assert_eq!(spans[1].zero_fill(), 0x1e00);
    assert_eq!(spans[2].file_bytes, 0);
    assert_eq!(spans[2].zero_fill(), 0x1000);
    let view = materialize_view(&parsed).unwrap();
    assert_eq!(view.len(), 0x4000);
    assert_eq!(view[0x1010], 0xcc);
    // The tail is legitimate address space: readable, and zero.
    assert!(view[0x1200..0x3000].iter().all(|byte| *byte == 0));
    assert!(view[0x3000..0x4000].iter().all(|byte| *byte == 0));
}

/// Every field the record carries set to its own distinct value, so a field
/// written into a neighbour's slot cannot read back as correct.
fn populated_image() -> Vec<u8> {
    let mut b = two_section_image();
    b[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());
    b[OPT + 40..OPT + 42].copy_from_slice(&10u16.to_le_bytes());
    b[OPT + 42..OPT + 44].copy_from_slice(&2u16.to_le_bytes());
    b[OPT + 48..OPT + 50].copy_from_slice(&6u16.to_le_bytes());
    b[OPT + 50..OPT + 52].copy_from_slice(&1u16.to_le_bytes());
    b[OPT + 64..OPT + 68].copy_from_slice(&0xabcd_1234u32.to_le_bytes());
    b[OPT + 68..OPT + 70].copy_from_slice(&3u16.to_le_bytes());
    b[OPT + 70..OPT + 72].copy_from_slice(&0x0160u16.to_le_bytes());
    b[OPT + 72..OPT + 80].copy_from_slice(&0x10_0000u64.to_le_bytes());
    b[OPT + 80..OPT + 88].copy_from_slice(&0x1000u64.to_le_bytes());
    b
}

#[test]
fn image_information_reports_the_headers_the_loader_reads() {
    let b = populated_image();
    let parsed = parse(&b).unwrap();
    let info = image_information(&parsed, 0x800).unwrap();
    assert_eq!(info.transfer_address, 0x1000_0000 + 0x1010);
    assert_eq!(info.maximum_stack_size, 0x10_0000);
    assert_eq!(info.committed_stack_size, 0x1000);
    assert_eq!(info.subsystem, 3);
    assert_eq!(info.subsystem_major, 6);
    assert_eq!(info.subsystem_minor, 1);
    assert_eq!(info.os_major, 10);
    assert_eq!(info.os_minor, 2);
    assert_eq!(info.image_characteristics, 0x2022);
    assert_eq!(info.dll_characteristics, 0x0160);
    assert_eq!(info.machine, IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(info.checksum, 0xabcd_1234);
    assert_eq!(info.file_size, 0x800);
    assert!(info.contains_code, "an executable section is code");
    assert!(info.dynamically_relocated(), "a dynamic-base image with code relocates");
}

#[test]
fn the_encoded_record_places_every_field_where_a_64_bit_query_reads_it() {
    let b = populated_image();
    let parsed = parse(&b).unwrap();
    let info = image_information(&parsed, 0x800).unwrap();
    let bytes = info.encode();
    assert_eq!(bytes.len(), SECTION_IMAGE_INFORMATION_BYTES);
    assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), info.transfer_address);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), info.maximum_stack_size);
    assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), info.committed_stack_size);
    assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), info.subsystem);
    assert_eq!(u16::from_le_bytes(bytes[36..38].try_into().unwrap()), info.subsystem_minor);
    assert_eq!(u16::from_le_bytes(bytes[38..40].try_into().unwrap()), info.subsystem_major);
    assert_eq!(u16::from_le_bytes(bytes[40..42].try_into().unwrap()), info.os_major);
    assert_eq!(u16::from_le_bytes(bytes[42..44].try_into().unwrap()), info.os_minor);
    assert_eq!(u16::from_le_bytes(bytes[44..46].try_into().unwrap()), info.image_characteristics);
    assert_eq!(u16::from_le_bytes(bytes[46..48].try_into().unwrap()), info.dll_characteristics);
    assert_eq!(u16::from_le_bytes(bytes[48..50].try_into().unwrap()), info.machine);
    assert_eq!(bytes[50], 1);
    assert_eq!(bytes[51], info.image_flags);
    assert_eq!(u32::from_le_bytes(bytes[52..56].try_into().unwrap()), info.loader_flags);
    // No field may read back correct because it and its neighbour agree.
    let values = [info.subsystem_minor, info.subsystem_major, info.os_major, info.os_minor,
        info.image_characteristics, info.dll_characteristics, info.machine];
    for pair in values.windows(2) { assert_ne!(pair[0], pair[1], "neighbouring fields must differ: {values:?}"); }
    assert_ne!(info.maximum_stack_size, info.committed_stack_size);
    assert_ne!(info.file_size, info.checksum);
    assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), info.file_size);
    assert_eq!(u32::from_le_bytes(bytes[60..64].try_into().unwrap()), info.checksum);
}

#[test]
fn a_view_at_another_address_reports_its_own_transfer_address() {
    let b = populated_image();
    let parsed = parse(&b).unwrap();
    let info = image_information(&parsed, 0x800).unwrap();
    let moved = info.at_base(0x7fff_0000_0000, parsed.entry_rva);
    assert_eq!(moved.transfer_address, 0x7fff_0000_0000 + 0x1010);
    assert_eq!(moved.encode()[8..], info.encode()[8..], "only the transfer address moves");
}

#[test]
fn an_image_without_a_dynamic_base_is_not_reported_relocatable() {
    let mut b = two_section_image();
    b[OPT + 70..OPT + 72].copy_from_slice(&0u16.to_le_bytes());
    let parsed = parse(&b).unwrap();
    assert!(!image_information(&parsed, 0x800).unwrap().dynamically_relocated());
}

fn catalog() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
        .join("target/artifacts/wine/x86_64/x86_64-windows");
    if root.join("ntdll.dll").is_file() { Some(root) } else { None }
}

/// Every module the guest stages must lay out, and the layout must cover the
/// image without overlap: a span that overlaps its neighbour would have one
/// section's protection silently win over another's.
#[test]
fn every_shipped_module_lays_out_a_disjoint_covering_view() {
    let Some(root) = catalog() else { eprintln!("pe: shipped catalog absent, skipped"); return };
    let mut count = 0usize;
    let mut tails = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str()).unwrap_or("");
        if extension != "dll" && extension != "exe" { continue; }
        let name = path.file_name().and_then(|value| value.to_str()).unwrap_or("").to_string();
        let Ok(blob) = std::fs::read(&path) else { continue };
        count += 1;
        // A module skipped because it would not parse is a module the loader
        // cannot map, so the audit must fail on it rather than pass over it.
        let parsed = match parse(&blob) { Ok(parsed) => parsed, Err(error) => { failures.push(format!("{name}: {error:?}")); continue } };
        let Ok(spans) = view_layout(&parsed) else { failures.push(format!("{name}: no layout")); continue };
        let mut previous_end = 0u32;
        for span in &spans {
            if span.rva < previous_end { failures.push(format!("{name}: span at {:#x} overlaps {:#x}", span.rva, previous_end)); }
            if span.rva + span.size > parsed.size_of_image { failures.push(format!("{name}: span at {:#x} leaves the image", span.rva)); }
            if span.zero_fill() != 0 { tails += 1; }
            previous_end = span.rva + span.size;
        }
        if image_information(&parsed, blob.len() as u64).is_err() { failures.push(format!("{name}: no image information")); }
    }
    assert!(count > 20, "the catalog must carry the module set, found {count}");
    assert!(failures.is_empty(), "{failures:?}");
    assert!(tails > 0, "shipped modules do place exports in a zero-filled tail");
}

/// A section that every view shares writes to needs one backing store shared
/// between those views. An image view here is private, so each process would
/// silently get its own copy. No module the guest stages carries such a
/// section — this fails the day one does, rather than diverging quietly.
#[test]
fn no_shipped_module_needs_a_shared_writable_section() {
    let Some(root) = catalog() else { eprintln!("pe: shipped catalog absent, skipped"); return };
    let mut count = 0usize;
    let mut carriers: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str()).unwrap_or("");
        if extension != "dll" && extension != "exe" { continue; }
        let Ok(blob) = std::fs::read(&path) else { continue };
        let Ok(parsed) = parse(&blob) else { continue };
        count += 1;
        let shared = shared_writable_sections(&parsed);
        if shared != 0 {
            carriers.push(format!("{}: {shared}", path.file_name().and_then(|v| v.to_str()).unwrap_or("")));
        }
    }
    assert!(count > 20, "the catalog must carry the module set, found {count}");
    assert!(carriers.is_empty(), "shared writable sections are not backed by a shared store yet: {carriers:?}");
}

/// The predicate itself must be able to see one.
#[test]
fn a_shared_writable_section_is_recognised() {
    let mut b = two_section_image();
    b[SEC2 + 36..SEC2 + 40].copy_from_slice(
        &(SectionFlags::MEM_READ | SectionFlags::MEM_WRITE | SectionFlags::MEM_SHARED).to_le_bytes());
    let parsed = parse(&b).unwrap();
    assert_eq!(shared_writable_sections(&parsed), 1);
    let plain = two_section_image();
    assert_eq!(shared_writable_sections(&parse(&plain).unwrap()), 0);
}

