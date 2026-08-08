use super::*;

#[test]
fn a_written_header_parses_back_to_the_same_instant() {
    let s = write_kmsg_hdr(1234, 567_000_000);
    assert_eq!(s, "====1234.567000-D\n");
    let h = parse_kmsg_hdr(s.as_bytes()).unwrap();
    assert_eq!((h.sec, h.nsec, h.compressed), (1234, 567_000_000, false));
    assert_eq!(h.len, s.len());
}

#[test]
fn the_body_starts_after_the_header() {
    let mut buf = write_kmsg_hdr(7, 0).into_bytes();
    buf.extend_from_slice(b"Panic#1 Part1\nlog text");
    let h = parse_kmsg_hdr(&buf).unwrap();
    assert_eq!(&buf[h.len..], b"Panic#1 Part1\nlog text");
}

#[test]
fn the_fraction_is_six_digits_so_the_field_width_is_fixed() {
    assert_eq!(write_kmsg_hdr(1, 1_000), "====1.000001-D\n");
    assert_eq!(write_kmsg_hdr(0, 0), "====0.000000-D\n");
}

#[test]
fn the_older_spelling_without_a_flag_is_accepted() {
    let h = parse_kmsg_hdr(b"====99.000500\nbody").unwrap();
    assert_eq!((h.sec, h.nsec, h.compressed), (99, 500_000, false));
    assert_eq!(h.len, 14);
}

#[test]
fn the_compressed_flag_is_read() {
    let h = parse_kmsg_hdr(b"====5.000000-C\n").unwrap();
    assert!(h.compressed);
}

#[test]
fn contents_this_kernel_did_not_write_are_refused() {
    // Nothing this kernel wrote — the whole point of the check.
    assert_eq!(parse_kmsg_hdr(b""), None);
    assert_eq!(parse_kmsg_hdr(b"random memory contents"), None);
    assert_eq!(parse_kmsg_hdr(&[0u8; 32]), None);
    // Marker present, rest malformed.
    assert_eq!(parse_kmsg_hdr(b"====\n"), None);
    assert_eq!(parse_kmsg_hdr(b"====12\n"), None);
    assert_eq!(parse_kmsg_hdr(b"====12.5"), None);
    assert_eq!(parse_kmsg_hdr(b"====12.000005-X\n"), None);
    // A fraction that is not a fraction.
    assert_eq!(parse_kmsg_hdr(b"====12.1000000-D\n"), None);
}

#[test]
fn the_core_header_names_the_reason() {
    assert_eq!(dump_header(DumpReason::Panic, 1, 1), b"Panic#1 Part1\n".to_vec());
    assert_eq!(dump_header(DumpReason::Shutdown, 12, 3), b"Shutdown#12 Part3\n".to_vec());
}
