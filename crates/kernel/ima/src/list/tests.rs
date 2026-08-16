use alloc::vec;
use alloc::vec::Vec;

use crate::hash::HashAlgo;
use crate::limits::DEFAULT_MEASURE_PCR;
use crate::list::*;
use crate::template::{lookup_desc, Event, TemplateEntry};

/// Records what was extended where, so a test can assert the value and the
/// register rather than only that an extend happened.
#[derive(Default)]
struct FakeTpm {
    ops: Vec<(u32, HashAlgo, Vec<u8>)>,
}

impl PcrExtend for FakeTpm {
    fn extend(&mut self, pcr: u32, algo: HashAlgo, digest: &[u8]) -> Result<(), ()> {
        self.ops.push((pcr, algo, digest.to_vec()));
        Ok(())
    }
}

struct DeadTpm;
impl PcrExtend for DeadTpm {
    fn extend(&mut self, _p: u32, _a: HashAlgo, _d: &[u8]) -> Result<(), ()> { Err(()) }
}

fn entry(name: &str, digest: &[u8], pcr: u32) -> TemplateEntry {
    let ev = Event::new(name, HashAlgo::Sha256, Some(digest));
    TemplateEntry::build(lookup_desc("ima-ng").unwrap(), &ev, pcr)
}

#[test]
fn a_record_extends_its_own_template_digest_not_the_file_digest() {
    let file_digest: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &file_digest, 10);
    let want = e.template_digest(HashAlgo::Sha256).unwrap();

    let mut list = MeasurementList::new(HashAlgo::Sha256);
    let mut tpm = FakeTpm::default();
    list.add(e, &mut tpm).unwrap();

    assert_eq!(tpm.ops.len(), 1);
    assert_eq!(tpm.ops[0].2, want);
    assert_ne!(tpm.ops[0].2, file_digest, "the file digest must not be what is extended");
    assert_eq!(list.entries()[0].template_digest, want);
}

#[test]
fn a_record_extends_the_register_its_rule_named() {
    let d: Vec<u8> = (0u8..32).collect();
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    let mut tpm = FakeTpm::default();
    list.add(entry("/bin/sh", &d, 11), &mut tpm).unwrap();
    assert_eq!(tpm.ops[0].0, 11, "the rule named register 11");
    list.add(entry("/bin/ls", &d, DEFAULT_MEASURE_PCR), &mut tpm).unwrap();
    assert_eq!(tpm.ops[1].0, DEFAULT_MEASURE_PCR);
    assert_eq!(pcr_for(None), DEFAULT_MEASURE_PCR);
    assert_eq!(pcr_for(Some(11)), 11);
}

#[test]
fn an_identical_record_is_not_measured_twice_into_the_same_register() {
    let d: Vec<u8> = (0u8..32).collect();
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    let mut tpm = FakeTpm::default();
    list.add(entry("/bin/sh", &d, 10), &mut tpm).unwrap();
    assert_eq!(list.add(entry("/bin/sh", &d, 10), &mut tpm), Err(AppendError::Exists));
    assert_eq!(list.len(), 1);
    assert_eq!(tpm.ops.len(), 1, "a duplicate must not extend the register again");

    // The same file into a different register is a different record.
    list.add(entry("/bin/sh", &d, 11), &mut tpm).unwrap();
    assert_eq!(list.len(), 2);

    // A different file is a different record.
    list.add(entry("/bin/ls", &d, 10), &mut tpm).unwrap();
    assert_eq!(list.len(), 3);
}

#[test]
fn deduplication_can_be_turned_off() {
    let d: Vec<u8> = (0u8..32).collect();
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    list.set_dedup(false);
    let mut tpm = FakeTpm::default();
    list.add(entry("/bin/sh", &d, 10), &mut tpm).unwrap();
    list.add(entry("/bin/sh", &d, 10), &mut tpm).unwrap();
    assert_eq!(list.len(), 2);
}

#[test]
fn a_violation_invalidates_the_register_and_is_never_deduplicated() {
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    let mut tpm = FakeTpm::default();
    let ev = Event { violation: true, ..Event::new("/bin/sh", HashAlgo::Sha256, None) };
    let e = TemplateEntry::build(lookup_desc("ima-ng").unwrap(), &ev, 10);
    list.add_violation(e.clone(), &mut tpm).unwrap();
    list.add_violation(e, &mut tpm).unwrap();

    assert_eq!(list.violations(), 2);
    assert_eq!(list.len(), 2, "violations are never suppressed as duplicates");
    // The register is extended with a value no digest can produce.
    assert_eq!(tpm.ops[0].2, vec![0xffu8; 32]);
    assert_eq!(invalidating_digest(HashAlgo::Sha1), vec![0xffu8; 20]);
    // The record itself carries a zero digest.
    assert_eq!(list.entries()[0].template_digest, vec![0u8; 32]);
    assert!(list.entries()[0].violation);
}

#[test]
fn a_suspended_list_accepts_nothing() {
    let d: Vec<u8> = (0u8..32).collect();
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    let mut tpm = FakeTpm::default();
    list.suspend();
    assert_eq!(list.add(entry("/bin/sh", &d, 10), &mut tpm), Err(AppendError::Suspended));
    assert!(list.is_empty());
    assert!(tpm.ops.is_empty());
}

#[test]
fn a_failed_extend_still_leaves_the_record_in_the_log() {
    let d: Vec<u8> = (0u8..32).collect();
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    list.add(entry("/bin/sh", &d, 10), &mut DeadTpm).unwrap();
    assert_eq!(list.len(), 1, "the log must show what was measured even without a TPM");
}

#[test]
fn a_list_using_an_algorithm_with_no_engine_measures_nothing() {
    let d: Vec<u8> = (0u8..32).collect();
    let mut list = MeasurementList::new(HashAlgo::Sm3_256);
    let mut tpm = FakeTpm::default();
    assert_eq!(list.add(entry("/bin/sh", &d, 10), &mut tpm), Err(AppendError::NoAlgo));
}

#[test]
fn the_extend_goes_through_the_platform_register_implementation() {
    // The arithmetic belongs to the TPM subsystem; this asserts the record's
    // digest reaches it and lands in the register the rule named.
    use tpm::pcr::Bank;
    const PLATFORM_PCR: usize = 24;
    let d: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &d, 10);
    let td = e.template_digest(HashAlgo::Sha256).unwrap();

    let mut bank = Bank::new(tpm::alg::Alg::Sha256);
    let before = bank.read(10).unwrap().to_vec();
    let want = tpm::pcr::extend_value(tpm::alg::Alg::Sha256, &before, &td).unwrap();

    let mut list = MeasurementList::new(HashAlgo::Sha256);
    list.add(e, &mut bank).unwrap();
    assert_eq!(bank.read(10).unwrap(), &want[..]);
    // No other register moved.
    for i in 0..PLATFORM_PCR {
        if i == 10 { continue; }
        let untouched = vec![tpm::pcr::reset_fill(i); 32];
        assert_eq!(bank.read(i).unwrap(), &untouched[..], "register {i} moved");
    }
}

#[test]
fn a_record_never_extends_a_bank_of_another_algorithm() {
    let d: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &d, 10);
    let mut bank = tpm::pcr::Bank::new(tpm::alg::Alg::Sha1);
    let before = bank.read(10).unwrap().to_vec();
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    list.add(e, &mut bank).unwrap();
    assert_eq!(bank.read(10).unwrap(), &before[..]);
    assert_eq!(bank_alg(HashAlgo::Sha256), Some(tpm::alg::Alg::Sha256));
    assert_eq!(bank_alg(HashAlgo::Md5), None);
}

// --- violations ----------------------------------------------------------

#[test]
fn opening_for_write_a_file_a_reader_measured_is_a_tomtou_violation() {
    let mut st = ViolationState::default();
    // A reader measures the file first.
    let emitted = rdwr_violation_check(&mut st, OpenCheck {
        for_write: false, readers: false, open_for_write: false,
        is_measured_inode: true, must_measure: true,
    });
    assert!(emitted.is_empty());
    assert!(st.may_emit_tomtou);

    // Then a writer arrives while the reader holds it open.
    let emitted = rdwr_violation_check(&mut st, OpenCheck {
        for_write: true, readers: true, open_for_write: false,
        is_measured_inode: true, must_measure: false,
    });
    assert_eq!(emitted, vec![Violation::ToMToU]);
    assert_eq!(Violation::ToMToU.cause(), "ToMToU");
    // Reported once per measurement, not once per open.
    let again = rdwr_violation_check(&mut st, OpenCheck {
        for_write: true, readers: true, open_for_write: false,
        is_measured_inode: true, must_measure: false,
    });
    assert!(again.is_empty());
}

#[test]
fn no_tomtou_for_a_file_nobody_measured() {
    let mut st = ViolationState::default();
    let emitted = rdwr_violation_check(&mut st, OpenCheck {
        for_write: true, readers: true, open_for_write: false,
        is_measured_inode: false, must_measure: false,
    });
    assert!(emitted.is_empty());
}

#[test]
fn measuring_a_file_a_writer_holds_open_is_an_open_writers_violation() {
    let mut st = ViolationState::default();
    let c = OpenCheck {
        for_write: false, readers: false, open_for_write: true,
        is_measured_inode: true, must_measure: true,
    };
    assert_eq!(rdwr_violation_check(&mut st, c), vec![Violation::OpenWriters]);
    assert_eq!(Violation::OpenWriters.cause(), "open_writers");
    // Not repeated while the writer is still there.
    assert!(rdwr_violation_check(&mut st, c).is_empty());
    // Once the last writer closes, a later reader can report it again.
    last_writer_closed(&mut st);
    assert_eq!(rdwr_violation_check(&mut st, c), vec![Violation::OpenWriters]);
}

#[test]
fn a_read_that_policy_does_not_measure_raises_nothing() {
    let mut st = ViolationState::default();
    let emitted = rdwr_violation_check(&mut st, OpenCheck {
        for_write: false, readers: false, open_for_write: true,
        is_measured_inode: true, must_measure: false,
    });
    assert!(emitted.is_empty());
    assert!(!st.may_emit_tomtou);
}
