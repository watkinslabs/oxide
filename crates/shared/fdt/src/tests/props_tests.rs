use alloc::vec::Vec;

use super::{virt_like, Fdt};
use crate::props::*;

#[test]
fn bootargs_are_read_and_nul_trimmed() {
    let blob = virt_like();
    assert_eq!(chosen_bootargs(&blob), Some(&b"console=ttyAMA0 root=/dev/vda2"[..]));
}

#[test]
fn bootargs_absent_or_empty_is_none_or_empty() {
    let no_chosen = Fdt::new().begin("").end().finish();
    assert_eq!(chosen_bootargs(&no_chosen), None);
    let empty = Fdt::new().begin("").begin("chosen").prop("bootargs", b"\0\0").end().end().finish();
    assert_eq!(chosen_bootargs(&empty), Some(&b""[..]));
}

#[test]
fn first_memory_region_reads_two_address_two_size_cells() {
    assert_eq!(first_memory_region(&virt_like()), Some((0x4000_0000, 0x8000_0000)));
}

#[test]
fn memory_node_without_unit_suffix_also_matches() {
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x1000_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x2000_0000u64.to_be_bytes());
    let blob = Fdt::new().begin("").begin("memory").prop("reg", &reg).end().end().finish();
    assert_eq!(first_memory_region(&blob), Some((0x1000_0000, 0x2000_0000)));
}

/// A node merely starting with "memory" (`memory-controller@0`) is a different
/// device; matching it would hand the PMM a controller's register window as RAM.
#[test]
fn memory_prefixed_node_is_not_a_memory_node() {
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x9000_0000u64.to_be_bytes());
    reg.extend_from_slice(&0x1000u64.to_be_bytes());
    let blob = Fdt::new().begin("").begin("memory-controller@0").prop("reg", &reg).end().end().finish();
    assert_eq!(first_memory_region(&blob), None);
}

#[test]
fn enum_cpus_uses_the_cpus_address_cells() {
    let blob = virt_like();
    let mut out = [0u64; 8];
    assert_eq!(enum_cpus(&blob, &mut out), 2);
    assert_eq!(&out[..2], &[0, 1]);
}

/// The FDT default is `#address-cells = 2`; a `/cpus` that omits it must fold
/// two cells, not one, or every MPIDR is read from the wrong half.
#[test]
fn enum_cpus_defaults_to_two_address_cells() {
    let mut reg = Vec::new();
    reg.extend_from_slice(&1u32.to_be_bytes());
    reg.extend_from_slice(&0x8000_0003u32.to_be_bytes());
    let blob = Fdt::new().begin("").begin("cpus").begin("cpu@0").prop("reg", &reg).end().end().end().finish();
    let mut out = [0u64; 4];
    assert_eq!(enum_cpus(&blob, &mut out), 1);
    assert_eq!(out[0], 0x1_8000_0003);
}

#[test]
fn enum_cpus_reports_the_full_count_past_the_output_capacity() {
    let mut f = Fdt::new();
    f.begin("").begin("cpus").prop_u32("#address-cells", 1);
    for i in 0..5u32 { f.begin("cpu@0").prop_u32("reg", i).end(); }
    let blob = f.end().end().finish();
    let mut out = [0u64; 2];
    assert_eq!(enum_cpus(&blob, &mut out), 5);
    assert_eq!(&out[..], &[0, 1]);
}

#[test]
fn pl011_clock_via_phandle() {
    assert_eq!(pl011_clock_hz(&virt_like()), Some(24_000_000));
}

#[test]
fn pl011_clock_direct_on_node() {
    let blob = Fdt::new().begin("").begin("pl011@9000000")
        .prop_str("compatible", "arm,pl011").prop_u32("clock-frequency", 48_000_000)
        .end().end().finish();
    assert_eq!(pl011_clock_hz(&blob), Some(48_000_000));
}

#[test]
fn pl011_clock_absent_returns_none() {
    let blob = Fdt::new().begin("").begin("memory").end().end().finish();
    assert_eq!(pl011_clock_hz(&blob), None);
}

/// `compatible` is a NUL-delimited string list; a substring match would accept
/// a different device (`arm,pl011-extended`) and reprogram the wrong baud.
#[test]
fn compatible_matching_is_whole_element_not_substring() {
    assert!(contains_string(b"arm,sbsa-uart\0arm,pl011\0", b"arm,pl011"));
    assert!(!contains_string(b"arm,pl011-extended\0", b"arm,pl011"));
}

#[test]
fn machine_model_prefers_model_then_compatible() {
    assert_eq!(machine_model(&virt_like()), Some(&b"linux,dummy-virt"[..]));
    let only_compat = Fdt::new().begin("").prop_str("compatible", "acme,board").end().finish();
    assert_eq!(machine_model(&only_compat), Some(&b"acme,board"[..]));
    let neither = Fdt::new().begin("").end().finish();
    assert_eq!(machine_model(&neither), None);
}

/// The boot path cannot hand the whole blob in: it must learn the length from
/// a prefix first. A reader that asks `parse_header` for that length gets
/// nothing on every blob, which is how the command line went unread on every
/// boot without anything going red.
#[test]
fn bootargs_via_prefix_reads_through_a_two_step_bounded_map() {
    let blob = virt_like();
    let got = bootargs_via_prefix(&blob[..8], |ts| {
        assert_eq!(ts, blob.len(), "the prefix must yield the whole blob's length");
        blob.get(..ts)
    });
    assert_eq!(got, Some(&b"console=ttyAMA0 root=/dev/vda2"[..]));
}

#[test]
fn bootargs_via_prefix_reads_nothing_from_a_prefix_that_is_not_a_blob() {
    assert_eq!(bootargs_via_prefix(&[0u8; 8], |_| Some(&[][..])), None);
    let blob = virt_like();
    // A mapper that cannot supply the length it was asked for yields nothing
    // rather than parsing a short blob.
    assert_eq!(bootargs_via_prefix(&blob[..8], |_| None), None);
}
