// Provenance for the FACS contract. Each offset is pinned by a table whose
// bytes are zero apart from the field under test, so a shifted offset moves
// the value out of the assertion and the test goes red. The rejection cases
// are the load-bearing half: the FACS is the one ACPI table the OS writes
// into, and writing a resume address into something that is not a FACS
// scribbles firmware memory.

use super::*;

const CONFORMANT_LEN: usize = 64;

fn blank(len: usize) -> [u8; 256] {
    let mut t = [0u8; 256];
    t[0] = b'F'; t[1] = b'A'; t[2] = b'C'; t[3] = b'S';
    let l = len as u32;
    t[4] = l as u8; t[5] = (l >> 8) as u8; t[6] = (l >> 16) as u8; t[7] = (l >> 24) as u8;
    t
}

fn put_u32(t: &mut [u8], off: usize, v: u32) {
    t[off] = v as u8; t[off + 1] = (v >> 8) as u8; t[off + 2] = (v >> 16) as u8; t[off + 3] = (v >> 24) as u8;
}

fn put_u64(t: &mut [u8], off: usize, v: u64) {
    let mut i = 0usize;
    while i < 8 { t[off + i] = (v >> (i * 8)) as u8; i += 1; }
}

#[test]
fn every_field_reads_from_its_architectural_offset() {
    let mut t = blank(CONFORMANT_LEN);
    put_u32(&mut t, 8, 0xdead_beef);
    put_u32(&mut t, 12, 0x0000_9000);
    put_u32(&mut t, 16, 0x0000_0003);
    put_u32(&mut t, 20, FACS_64BIT_WAKE);
    put_u64(&mut t, 24, 0xffff_0000_1234_5678);
    t[32] = 2;
    let f = parse_facs(&t[..CONFORMANT_LEN]).expect("conformant table parses");
    assert_eq!(f.length, CONFORMANT_LEN as u32);
    assert_eq!(f.hardware_signature, 0xdead_beef);
    assert_eq!(f.firmware_waking_vector, 0x9000);
    assert_eq!(f.global_lock, 3);
    assert_eq!(f.flags, FACS_64BIT_WAKE);
    assert_eq!(f.xfirmware_waking_vector, 0xffff_0000_1234_5678);
    assert_eq!(f.version, 2);
    // The two vector offsets the writer uses must be the ones parsed here.
    assert_eq!(vector32_offset(), 12);
    assert_eq!(xvector_offset(), 24);
}

#[test]
fn a_wrong_signature_is_not_a_facs() {
    let mut t = blank(CONFORMANT_LEN);
    t[0] = b'F'; t[1] = b'A'; t[2] = b'C'; t[3] = b'P';
    assert_eq!(parse_facs(&t[..CONFORMANT_LEN]), None);
    // A single wrong byte anywhere in the signature is enough.
    for i in 0..4 {
        let mut t = blank(CONFORMANT_LEN);
        t[i] = 0;
        assert_eq!(parse_facs(&t[..CONFORMANT_LEN]), None, "byte {i} of the signature ignored");
    }
}

#[test]
fn implausible_declared_lengths_are_rejected() {
    // Shorter than the consumed fields.
    let mut t = blank(CONFORMANT_LEN);
    put_u32(&mut t, 4, (FACS_MIN_LEN - 1) as u32);
    assert_eq!(parse_facs(&t[..CONFORMANT_LEN]), None);
    // Zero length — the shape a firmware pointer into unwritten memory has.
    let mut t = blank(CONFORMANT_LEN);
    put_u32(&mut t, 4, 0);
    assert_eq!(parse_facs(&t[..CONFORMANT_LEN]), None);
    // Beyond any plausible firmware table.
    let mut t = blank(CONFORMANT_LEN);
    put_u32(&mut t, 4, (FACS_MAX_LEN + 1) as u32);
    assert_eq!(parse_facs(&t[..CONFORMANT_LEN]), None);
}

#[test]
fn a_declared_length_the_bytes_do_not_cover_is_rejected() {
    // The shim copies a bounded window; a table claiming more than was read
    // must not be published, or uninitialised bytes become table content.
    let t = blank(128);
    assert_eq!(parse_facs(&t[..64]), None);
    assert!(parse_facs(&t[..128]).is_some());
}

#[test]
fn a_short_table_carries_no_extended_vector() {
    // At or below the extended threshold the 64-bit vector and the version
    // byte do not exist, whatever the bytes past the end happen to hold.
    let mut t = blank(FACS_EXTENDED_MIN_LEN as usize);
    put_u64(&mut t, 24, 0xffff_ffff_ffff_ffff);
    t[32] = 9;
    let f = parse_facs(&t[..64]).expect("a 32-byte table still parses");
    assert_eq!(f.xfirmware_waking_vector, 0);
    assert_eq!(f.version, 0);
}

#[test]
fn the_thirty_two_bit_vector_is_always_written() {
    for len in [FACS_MIN_LEN as u32, FACS_EXTENDED_MIN_LEN, 64] {
        for version in [0u8, 1, 2] {
            let f = Facs { length: len, version, ..Default::default() };
            assert_eq!(waking_vector_writes(&f, 0x9000, 0).vector32, 0x9000,
                "len {len} version {version} skipped the 32-bit vector");
        }
    }
}

#[test]
fn the_extended_vector_is_cleared_on_a_version_zero_table() {
    // Leaving a stale 64-bit vector behind makes firmware resume through it
    // in protected mode and never reach the real-mode stub.
    let f = Facs { length: 64, version: 0, ..Default::default() };
    assert_eq!(waking_vector_writes(&f, 0x9000, 0xdead_beef),
               WakingVectorWrites { vector32: 0x9000, xvector: Some(0) });
}

#[test]
fn the_extended_vector_is_written_only_on_a_long_versioned_table() {
    let f = Facs { length: 64, version: 1, ..Default::default() };
    assert_eq!(waking_vector_writes(&f, 0x9000, 0x1_0000_0000),
               WakingVectorWrites { vector32: 0x9000, xvector: Some(0x1_0000_0000) });
    // A table too short to hold the field is left alone entirely.
    let f = Facs { length: FACS_EXTENDED_MIN_LEN, version: 1, ..Default::default() };
    assert_eq!(waking_vector_writes(&f, 0x9000, 0x1_0000_0000),
               WakingVectorWrites { vector32: 0x9000, xvector: None });
}

#[test]
fn the_real_mode_resume_path_clears_the_extended_vector() {
    // This port publishes a real-mode entry point, so the 64-bit vector it
    // asks for is zero; the write must still happen on a long table.
    let f = Facs { length: 64, version: 1, ..Default::default() };
    let w = waking_vector_writes(&f, 0x9000, 0);
    assert_eq!(w.vector32, 0x9000);
    assert_eq!(w.xvector, Some(0));
}
