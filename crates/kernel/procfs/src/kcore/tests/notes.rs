// Byte-level provenance for the note segment.

use super::*;
extern crate std;
use std::string::String;

fn u32_at(b: &[u8], at: usize) -> u32 { u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) }

/// Walk the segment the way a consumer does — header, padded name, padded
/// descriptor — and yield `(name, type, descriptor)` for each note.
fn walk(seg: &[u8]) -> alloc::vec::Vec<(String, u32, alloc::vec::Vec<u8>)> {
    let mut out = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i + NHDR_SIZE <= seg.len() {
        let namesz = u32_at(seg, i) as usize;
        let descsz = u32_at(seg, i + 4) as usize;
        let ty = u32_at(seg, i + 8);
        let name_at = i + NHDR_SIZE;
        let desc_at = name_at + align4(namesz);
        let name = String::from_utf8_lossy(&seg[name_at..name_at + namesz - 1]).into_owned();
        out.push((name, ty, seg[desc_at..desc_at + descsz].to_vec()));
        i = desc_at + align4(descsz);
    }
    assert_eq!(i, seg.len(), "the walk must land exactly on the end of the segment");
    out
}

#[test]
fn a_note_name_and_descriptor_are_each_padded_to_four_bytes() {
    // The padding is what a consumer adds to reach the NEXT note, so an
    // unpadded note does not corrupt itself — it corrupts everything after it.
    let mut seg = alloc::vec::Vec::new();
    append(&mut seg, "AB", 7, b"xyz");
    append(&mut seg, "LONGERNAME", 9, b"12345");
    let notes = walk(&seg);
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0], (String::from("AB"), 7, b"xyz".to_vec()));
    assert_eq!(notes[1], (String::from("LONGERNAME"), 9, b"12345".to_vec()));
    assert_eq!(seg.len() % 4, 0);
}

#[test]
fn a_note_name_length_counts_its_terminator() {
    let mut seg = alloc::vec::Vec::new();
    append(&mut seg, NAME_CORE, NT_PRSTATUS, b"");
    // A length that omitted the NUL makes the descriptor start one byte early
    // for every name whose length is already a multiple of four.
    assert_eq!(u32_at(&seg, 0), NAME_CORE.len() as u32 + 1);
    assert_eq!(&seg[NHDR_SIZE..NHDR_SIZE + 5], b"CORE\0");
}

#[test]
fn the_segment_carries_the_two_process_notes_then_the_core_information_note() {
    let seg = segment(PRSTATUS_SIZE_X86_64, b"root=/dev/vda ro", "1.2.3", 4096, 0xFFFF_FFFF_8000_0000);
    let notes = walk(&seg);
    assert_eq!(notes.len(), 3);
    assert_eq!(notes[0].0, NAME_CORE);
    assert_eq!(notes[0].1, NT_PRSTATUS);
    assert_eq!(notes[1].0, NAME_CORE);
    assert_eq!(notes[1].1, NT_PRPSINFO);
    // The core-information note is identified by its NAME, not its type: its
    // type is zero, which every other note name also uses for something else.
    assert_eq!(notes[2].0, NAME_COREINFO);
    assert_eq!(notes[2].1, NT_COREINFO);
}

#[test]
fn the_process_status_descriptor_keeps_its_arch_size_while_reporting_nothing() {
    // The kernel is still running, so there is no stopped register set — but
    // the LENGTH is what a consumer walks past, so it stays the arch's.
    for size in [PRSTATUS_SIZE_X86_64, PRSTATUS_SIZE_AARCH64] {
        let seg = segment(size, b"", "1", 4096, 0);
        let notes = walk(&seg);
        assert_eq!(notes[0].2.len(), size);
        assert!(notes[0].2.iter().all(|&b| b == 0));
    }
    assert_ne!(PRSTATUS_SIZE_X86_64, PRSTATUS_SIZE_AARCH64);
}

#[test]
fn the_process_information_descriptor_places_its_fields_at_the_abi_offsets() {
    let d = prpsinfo(b"root=/dev/vda ro quiet");
    assert_eq!(d.len(), PRPSINFO_SIZE);
    assert_eq!(d[1], STATE_RUNNING);
    assert_eq!(&d[40..47], SUBJECT_NAME);
    assert_eq!(d[47], 0);
    assert_eq!(&d[56..78], b"root=/dev/vda ro quiet");
    assert_eq!(d[78], 0);
}

#[test]
fn an_oversized_name_or_argument_is_truncated_and_still_terminated() {
    // A field filled to its last byte is read past its end by anything that
    // scans for the terminator.
    let d = prpsinfo(&[b'x'; 500]);
    assert_eq!(d.len(), PRPSINFO_SIZE);
    assert_eq!(d[56 + PRPSINFO_PSARGS_LEN - 1], 0);
    assert_eq!(&d[56..56 + PRPSINFO_PSARGS_LEN - 1], &[b'x'; PRPSINFO_PSARGS_LEN - 1]);
    assert_eq!(d[40 + PRPSINFO_FNAME_LEN - 1], 0);
}

#[test]
fn the_core_information_note_names_the_text_base_in_hex() {
    // This line is the only way a consumer learns where this kernel's text
    // begins. A decimal value parses, as a completely different address.
    let d = coreinfo("1.2.3-oxide", 4096, 0xFFFF_FFFF_8100_0000);
    let text = String::from_utf8(d).unwrap();
    assert!(text.contains("OSRELEASE=1.2.3-oxide\n"), "{text}");
    assert!(text.contains("PAGESIZE=4096\n"), "{text}");
    assert!(text.contains("SYMBOL(_stext)=ffffffff81000000\n"), "{text}");
    assert!(text.ends_with('\n'));
}
