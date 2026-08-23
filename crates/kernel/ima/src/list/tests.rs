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
    fn extend(&mut self, pcr: u32, algo: HashAlgo, digest: &[u8]) -> Result<(), ExtendError> {
        self.ops.push((pcr, algo, digest.to_vec()));
        Ok(())
    }
}

struct DeadTpm;
impl PcrExtend for DeadTpm {
    fn extend(&mut self, _p: u32, _a: HashAlgo, _d: &[u8]) -> Result<(), ExtendError> {
        Err(ExtendError { code: -1 })
    }
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
fn the_records_own_digest_and_register_reach_the_extend() {
    // A measurement must arrive at the chip carrying the record's template
    // digest, in the register the rule named. The seam is `PcrExtend`; there
    // is no kernel-side register to inspect, because a PCR lives in hardware.
    let d: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &d, 10);
    let td = e.template_digest(HashAlgo::Sha256).unwrap();

    let mut tpm = FakeTpm::default();
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    list.add(e, &mut tpm).unwrap();

    assert_eq!(tpm.ops.len(), 1, "exactly one extend per record");
    assert_eq!(tpm.ops[0].0, 10, "extended the register the rule named");
    assert_eq!(tpm.ops[0].1, HashAlgo::Sha256);
    assert_eq!(tpm.ops[0].2, td, "extended the record's own template digest");
}

#[test]
fn a_measurement_with_no_chip_is_logged_and_not_extended() {
    // The reference logs the measurement and returns success when no chip was
    // found. The log is still useful; it is simply unanchored, and saying so
    // is better than failing every measurement on a machine without a TPM.
    let d: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &d, 10);
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    assert!(list.add(e, &mut NoTpm).is_ok());
    assert_eq!(list.len(), 1, "the record is still in the log");
}

#[test]
fn a_chip_that_refuses_the_extend_keeps_the_record_and_counts_the_failure() {
    // The reference keeps the entry and reports the TPM failure separately —
    // the add succeeds, because an unanchored log still records what ran. What
    // must NOT happen is the failure vanishing: a chip refusing every extend
    // would then produce a log indistinguishable from an anchored one.
    let d: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &d, 10);
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    assert!(list.add(e, &mut DeadTpm).is_ok(), "the record is kept");
    assert_eq!(list.len(), 1);
    assert_eq!(list.tpm_failures(), 1, "the refused extend is visible");
}

#[test]
fn an_anchored_measurement_counts_no_failure() {
    let d: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &d, 10);
    let mut list = MeasurementList::new(HashAlgo::Sha256);
    list.add(e, &mut FakeTpm::default()).unwrap();
    assert_eq!(list.tpm_failures(), 0);
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

// --- end to end: IMA -> chip -> wire -----------------------------------

/// A chip that records the command bytes IMA's measurement produced. Shared
/// with the test through `log` so the sent bytes are still readable after
/// `Chip::new` has taken ownership of the transport.
struct WireChip { log: alloc::rc::Rc<core::cell::RefCell<Vec<Vec<u8>>>> }

impl tpm::Transport for WireChip {
    fn send(&mut self, cmd: &[u8]) -> Result<(), tpm::TransportError> {
        self.log.borrow_mut().push(cmd.to_vec());
        Ok(())
    }
    fn recv(&mut self, out: &mut [u8]) -> Result<usize, tpm::TransportError> {
        // Bare success header: tag, size, rc.
        let rsp: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0];
        out[..10].copy_from_slice(&rsp);
        Ok(10)
    }
}

#[test]
fn a_measurement_travels_from_the_list_to_the_wire() {
    // The end-to-end claim this whole subsystem rests on: appending a record
    // puts that record's template digest into a command addressed to the
    // register the rule named. Nothing kernel-side is inspected, because
    // nothing kernel-side is what a verifier will read.
    let d: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &d, 10);
    let td = e.template_digest(HashAlgo::Sha256).unwrap();

    let banks = tpm::AllocatedBanks::new(&[tpm::Alg::Sha256]).unwrap();
    let log = alloc::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let mut chip = tpm::Chip::new(banks, WireChip { log: log.clone() });

    let mut list = MeasurementList::new(HashAlgo::Sha256);
    list.add(e, &mut chip).unwrap();
    assert_eq!(list.tpm_failures(), 0, "the extend was accepted");

    let sent = log.borrow();
    assert_eq!(sent.len(), 1, "one entry, one extend command");
    assert!(sent[0].windows(td.len()).any(|w| w == td.as_slice()),
            "the wire command did not carry the record's template digest");
}

#[test]
fn a_chip_whose_banks_do_not_match_refuses_rather_than_extending_partially() {
    // IMA measures under one algorithm. A chip with two allocated banks needs
    // a digest for each; extending only one would leave the other recording a
    // different history, so the measurement is counted as unanchored instead.
    let d: Vec<u8> = (0u8..32).collect();
    let e = entry("/bin/sh", &d, 10);
    let banks = tpm::AllocatedBanks::new(&[tpm::Alg::Sha1, tpm::Alg::Sha256]).unwrap();
    let log = alloc::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let mut chip = tpm::Chip::new(banks, WireChip { log });

    let mut list = MeasurementList::new(HashAlgo::Sha256);
    list.add(e, &mut chip).unwrap();
    assert_eq!(list.len(), 1, "the record is still logged");
    assert_eq!(list.tpm_failures(), 1, "and it is marked unanchored");
}
