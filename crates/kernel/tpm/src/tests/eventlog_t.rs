// Event log. The log is firmware-supplied and its own count and size fields
// drive the walk, so every test here is about what happens when those fields
// lie: a record must never be produced from bytes outside the buffer, and a
// record whose digest list cannot be sized must stop the walk rather than
// resynchronising at a guessed offset.

use alloc::vec;
use alloc::vec::Vec;

use crate::alg::Alg;
use crate::eventlog::{
    AlgSize, Event1, Event2, LogError, SpecId, Tpm1Log, Tpm1LogBuilder, Tpm2Log, Tpm2LogBuilder,
    EV_ACTION, EV_IPL, EV_SEPARATOR, TCG_EVENT1_DIGEST_LEN, TCG_EVENT1_HEADER_LEN,
};

fn banks() -> Vec<AlgSize> {
    vec![AlgSize { alg_id: Alg::Sha1.id(), digest_size: 20 },
         AlgSize { alg_id: Alg::Sha256.id(), digest_size: 32 }]
}

fn built_log() -> Vec<u8> {
    let mut b = Tpm2LogBuilder::new(0, 0, 2, 0, 2, &banks(), b"oxide").unwrap();
    let d1 = [0x11u8; 20];
    let d256 = [0x22u8; 32];
    b.append(0, EV_SEPARATOR, &[(Alg::Sha1.id(), &d1[..]), (Alg::Sha256.id(), &d256[..])], b"sep").unwrap();
    b.append(10, EV_IPL, &[(Alg::Sha1.id(), &d1[..]), (Alg::Sha256.id(), &d256[..])], b"boot loader").unwrap();
    b.append(10, EV_ACTION, &[(Alg::Sha1.id(), &d1[..]), (Alg::Sha256.id(), &d256[..])], b"").unwrap();
    b.finish()
}

#[test]
fn the_header_declares_the_banks_the_records_carry() {
    let log = built_log();
    let spec = SpecId::parse(&log).unwrap();
    assert_eq!(spec.algs, banks());
    assert_eq!(spec.spec_version_major, 2);
    assert_eq!(spec.vendor_info_len, 5);
    assert_eq!(spec.digest_size(Alg::Sha256.id()).unwrap(), 32);
    assert_eq!(spec.digest_size(0x1234), Err(LogError::UnknownAlg(0x1234)));
    assert_eq!(spec.record_len, TCG_EVENT1_HEADER_LEN + 16 + 4 + 4 + 4 + 8 + 1 + 5);
}

#[test]
fn a_built_log_walks_back_to_what_was_appended() {
    let log = built_log();
    let parsed = Tpm2Log::parse(&log).unwrap();
    let events: Vec<Event2> = parsed.events().collect();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].pcr_idx, 0);
    assert_eq!(events[0].event_type, EV_SEPARATOR);
    assert_eq!(events[0].event, b"sep");
    assert_eq!(events[0].digest(Alg::Sha1.id()).unwrap(), &[0x11u8; 20]);
    assert_eq!(events[0].digest(Alg::Sha256.id()).unwrap(), &[0x22u8; 32]);
    assert_eq!(events[0].digest(Alg::Sha512.id()), None);
    assert_eq!(events[1].pcr_idx, 10);
    assert_eq!(events[1].event, b"boot loader");
    assert_eq!(events[2].event_type, EV_ACTION);
    assert!(events[2].event.is_empty());
}

#[test]
fn a_truncated_final_record_ends_the_walk_instead_of_overrunning() {
    let log = built_log();
    for cut in 1..40usize {
        if cut >= log.len() { break; }
        let short = &log[..log.len() - cut];
        let parsed = match Tpm2Log::parse(short) { Ok(p) => p, Err(_) => continue };
        // Whatever survives, the walk terminates and every record it yields
        // lies entirely inside the buffer.
        let mut end = parsed.spec().record_len;
        for e in parsed.events() { end += e.record_len; }
        assert!(end <= short.len(), "walk ran to {end} in a {}-byte log", short.len());
    }
}

#[test]
fn a_record_claiming_more_digests_than_the_log_declares_is_refused() {
    let spec = SpecId::parse(&built_log()).unwrap();
    let mut rec = Vec::new();
    rec.extend_from_slice(&0u32.to_le_bytes());
    rec.extend_from_slice(&EV_IPL.to_le_bytes());
    rec.extend_from_slice(&3u32.to_le_bytes());
    rec.extend_from_slice(&Alg::Sha1.id().to_le_bytes());
    rec.extend_from_slice(&[0x11; 20]);
    rec.extend_from_slice(&Alg::Sha256.id().to_le_bytes());
    rec.extend_from_slice(&[0x22; 32]);
    rec.extend_from_slice(&Alg::Sha512.id().to_le_bytes());
    rec.extend_from_slice(&[0x33; 64]);
    rec.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(Event2::parse(&rec, &spec), Err(LogError::DigestCount { expected: 2, got: 3 }));
}

#[test]
fn a_record_naming_an_unsized_algorithm_is_refused() {
    let spec = SpecId::parse(&built_log()).unwrap();
    let mut rec = Vec::new();
    rec.extend_from_slice(&0u32.to_le_bytes());
    rec.extend_from_slice(&EV_IPL.to_le_bytes());
    rec.extend_from_slice(&2u32.to_le_bytes());
    rec.extend_from_slice(&Alg::Sha1.id().to_le_bytes());
    rec.extend_from_slice(&[0x11; 20]);
    rec.extend_from_slice(&0x1234u16.to_le_bytes());
    rec.extend_from_slice(&[0x22; 32]);
    rec.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(Event2::parse(&rec, &spec), Err(LogError::UnknownAlg(0x1234)));
}

#[test]
fn an_event_size_past_the_end_of_the_buffer_is_refused() {
    let spec = SpecId::parse(&built_log()).unwrap();
    let mut rec = Vec::new();
    rec.extend_from_slice(&0u32.to_le_bytes());
    rec.extend_from_slice(&EV_IPL.to_le_bytes());
    rec.extend_from_slice(&2u32.to_le_bytes());
    rec.extend_from_slice(&Alg::Sha1.id().to_le_bytes());
    rec.extend_from_slice(&[0x11; 20]);
    rec.extend_from_slice(&Alg::Sha256.id().to_le_bytes());
    rec.extend_from_slice(&[0x22; 32]);
    // Declares 4096 bytes of event data; four are present.
    rec.extend_from_slice(&4096u32.to_le_bytes());
    rec.extend_from_slice(&[0xEE; 4]);
    assert_eq!(Event2::parse(&rec, &spec), Err(LogError::Truncated { need: 4096, have: 4 }));
}

#[test]
fn the_terminator_record_ends_the_log() {
    let spec = SpecId::parse(&built_log()).unwrap();
    let mut rec = Vec::new();
    rec.extend_from_slice(&0u32.to_le_bytes());
    rec.extend_from_slice(&0u32.to_le_bytes());
    rec.extend_from_slice(&2u32.to_le_bytes());
    rec.extend_from_slice(&Alg::Sha1.id().to_le_bytes());
    rec.extend_from_slice(&[0; 20]);
    rec.extend_from_slice(&Alg::Sha256.id().to_le_bytes());
    rec.extend_from_slice(&[0; 32]);
    rec.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(Event2::parse(&rec, &spec), Err(LogError::EndOfLog));

    let mut log = built_log();
    let before = Tpm2Log::parse(&log).unwrap().events().count();
    log.extend_from_slice(&rec);
    log.extend_from_slice(&rec);
    assert_eq!(Tpm2Log::parse(&log).unwrap().events().count(), before);
}

#[test]
fn a_header_that_is_not_a_specification_event_is_refused() {
    let good = built_log();

    let mut bad = good.clone();
    bad[0] = 1; // names a register other than zero
    assert!(matches!(SpecId::parse(&bad), Err(LogError::BadHeader(_))));

    let mut bad = good.clone();
    bad[4] = 5; // not a no-action event
    assert!(matches!(SpecId::parse(&bad), Err(LogError::BadHeader(_))));

    let mut bad = good.clone();
    bad[8] = 1; // non-zero digest
    assert!(matches!(SpecId::parse(&bad), Err(LogError::BadHeader(_))));

    let mut bad = good.clone();
    bad[TCG_EVENT1_HEADER_LEN] = b'X'; // signature
    assert_eq!(SpecId::parse(&bad), Err(LogError::BadSignature));

    for n in 0..TCG_EVENT1_HEADER_LEN {
        assert!(matches!(SpecId::parse(&good[..n]), Err(LogError::Truncated { .. }) | Err(LogError::BadHeader(_))));
    }
}

#[test]
fn a_header_declaring_no_algorithms_is_refused() {
    assert!(matches!(Tpm2LogBuilder::new(0, 0, 2, 0, 2, &[], b""), Err(LogError::NoAlgorithms)));
    let good = built_log();
    let mut bad = good.clone();
    // Zero the algorithm count inside the payload.
    let off = TCG_EVENT1_HEADER_LEN + 16 + 4 + 4;
    bad[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(SpecId::parse(&bad), Err(LogError::NoAlgorithms));
}

#[test]
fn the_builder_refuses_a_record_that_does_not_match_the_header() {
    let mut b = Tpm2LogBuilder::new(0, 0, 2, 0, 2, &banks(), b"").unwrap();
    let d1 = [0x11u8; 20];
    let d256 = [0x22u8; 32];
    assert_eq!(b.append(0, EV_IPL, &[(Alg::Sha1.id(), &d1[..])], b""),
               Err(LogError::DigestCount { expected: 2, got: 1 }));
    assert_eq!(b.append(0, EV_IPL, &[(Alg::Sha1.id(), &d256[..]), (Alg::Sha256.id(), &d256[..])], b""),
               Err(LogError::DigestLen { alg_id: Alg::Sha1.id(), expected: 20, got: 32 }));
    assert_eq!(b.append(0, EV_IPL, &[(Alg::Sha512.id(), &d1[..]), (Alg::Sha256.id(), &d256[..])], b""),
               Err(LogError::UnknownAlg(Alg::Sha1.id())));
}

#[test]
fn fixed_format_records_walk_back_to_what_was_appended() {
    let mut b = Tpm1LogBuilder::new();
    b.append(0, EV_SEPARATOR, &[0x11; 20], b"sep").unwrap();
    b.append(4, EV_IPL, &[0x22; 20], b"kernel").unwrap();
    let log = b.finish();
    let events: Vec<Event1> = Tpm1Log::new(&log).events().collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].pcr_idx, 0);
    assert_eq!(events[0].digest, &[0x11u8; 20]);
    assert_eq!(events[0].event, b"sep");
    assert_eq!(events[1].pcr_idx, 4);
    assert_eq!(events[1].event, b"kernel");
    assert_eq!(events[1].record_len, TCG_EVENT1_HEADER_LEN + 6);
}

#[test]
fn a_fixed_format_record_is_bounded_by_the_buffer() {
    let mut b = Tpm1LogBuilder::new();
    b.append(0, EV_IPL, &[0x11; 20], b"0123456789").unwrap();
    let log = b.finish();
    for cut in 1..=10usize {
        let short = &log[..log.len() - cut];
        assert!(matches!(Event1::parse(short), Err(LogError::Truncated { .. })));
        assert_eq!(Tpm1Log::new(short).events().count(), 0);
    }
    assert_eq!(b_terminator_count(), 0);
}

fn b_terminator_count() -> usize {
    let mut term = Vec::new();
    term.extend_from_slice(&0u32.to_le_bytes());
    term.extend_from_slice(&0u32.to_le_bytes());
    term.extend_from_slice(&[0u8; TCG_EVENT1_DIGEST_LEN]);
    term.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(Event1::parse(&term), Err(LogError::EndOfLog));
    Tpm1Log::new(&term).events().count()
}

#[test]
fn a_fixed_format_digest_must_be_the_declared_width() {
    let mut b = Tpm1LogBuilder::new();
    assert_eq!(b.append(0, EV_IPL, &[0x11; 32], b""),
               Err(LogError::DigestLen { alg_id: 0, expected: 20, got: 32 }));
}
