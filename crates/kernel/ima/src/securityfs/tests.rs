use alloc::vec::Vec;

use crate::hash::{hex, HashAlgo};
use crate::list::{ExtendError, MeasurementList, PcrExtend};
use crate::policy::parse::parse_rule;
use crate::securityfs::*;
use crate::template::{lookup_desc, Event, TemplateEntry};

struct NoTpm;
impl PcrExtend for NoTpm {
    fn extend(&mut self, _p: u32, _a: HashAlgo, _d: &[u8]) -> Result<(), ExtendError> { Ok(()) }
}

fn list_with(names: &[&str]) -> MeasurementList {
    let mut l = MeasurementList::new(HashAlgo::Sha256);
    for (i, n) in names.iter().enumerate() {
        let d: Vec<u8> = (i as u8..i as u8 + 32).collect();
        let ev = Event::new(n, HashAlgo::Sha256, Some(&d));
        let e = TemplateEntry::build(lookup_desc("ima-ng").unwrap(), &ev, 10);
        l.add(e, &mut NoTpm).unwrap();
    }
    l
}

#[test]
fn the_file_names_are_the_ones_the_tree_exposes() {
    assert_eq!(IMA_DIR, "ima");
    assert_eq!(F_ASCII, "ascii_runtime_measurements");
    assert_eq!(F_BINARY, "binary_runtime_measurements");
    assert_eq!(F_COUNT, "runtime_measurements_count");
    assert_eq!(F_VIOLATIONS, "violations");
    assert_eq!(F_POLICY, "policy");
}

#[test]
fn the_ascii_file_is_one_line_per_record_in_order() {
    let l = list_with(&["/bin/sh", "/bin/ls"]);
    let text = ascii_runtime_measurements(&l);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].ends_with("/bin/sh"));
    assert!(lines[1].ends_with("/bin/ls"));
    for (line, e) in lines.iter().zip(l.entries()) {
        assert!(line.contains(&hex(&e.template_digest)));
        assert!(line.contains("ima-ng"));
        assert!(line.starts_with("10 "));
    }
}

#[test]
fn the_binary_file_is_the_records_concatenated() {
    let l = list_with(&["/bin/sh", "/bin/ls"]);
    let bin = binary_runtime_measurements(&l);
    let mut want: Vec<u8> = Vec::new();
    for e in l.entries() { want.extend_from_slice(&e.entry.binary_record(&e.template_digest)); }
    assert_eq!(bin, want);
    // The first record starts with its register index.
    assert_eq!(&bin[0..4], &10u32.to_le_bytes());
}

#[test]
fn the_counters_are_decimal_lines() {
    let mut l = list_with(&["/bin/sh", "/bin/ls", "/bin/cat"]);
    assert_eq!(runtime_measurements_count(&l), "3\n");
    assert_eq!(violations(&l), "0\n");

    let ev = Event { violation: true, ..Event::new("/bin/sh", HashAlgo::Sha256, None) };
    let e = TemplateEntry::build(lookup_desc("ima-ng").unwrap(), &ev, 10);
    l.add_violation(e, &mut NoTpm).unwrap();
    assert_eq!(violations(&l), "1\n");
    assert_eq!(runtime_measurements_count(&l), "4\n");

    let empty = MeasurementList::new(HashAlgo::Sha256);
    assert_eq!(runtime_measurements_count(&empty), "0\n");
}

#[test]
fn the_policy_file_lists_the_rules_in_force() {
    let rules = [
        parse_rule("dont_measure fsmagic=0x9fa0").unwrap(),
        parse_rule("measure func=BPRM_CHECK mask=MAY_EXEC").unwrap(),
    ];
    let text = policy(&rules);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("dont_measure fsmagic=0x9fa0"));
    assert!(lines[1].starts_with("measure func=BPRM_CHECK"));
    // Every rendered line parses back, so the file is a usable record.
    for l in lines { assert!(parse_rule(l).is_ok(), "{l:?}"); }
}

#[test]
fn an_empty_tree_renders_empty_rather_than_absent() {
    let l = MeasurementList::new(HashAlgo::Sha256);
    assert_eq!(ascii_runtime_measurements(&l), "");
    assert!(binary_runtime_measurements(&l).is_empty());
    assert_eq!(policy(&[]), "");
}
