use alloc::vec::Vec;

use super::*;

fn text(v: &[u8]) -> &str { core::str::from_utf8(v).expect("record text is ASCII") }

/// A verdict with no justification still produces a record: "a daemon decided
/// this and would not say why" is what an auditor needs to see.
#[test]
fn a_verdict_without_a_justification_reports_unknown_trust() {
    let b = fanotify_body(2, None);
    assert_eq!(text(&b), "resp=2 fan_type=0 fan_info=0 subj_trust=2 obj_trust=2");
}

#[test]
fn a_verdict_with_a_rule_names_the_rule_in_hex_and_both_trust_values() {
    let b = fanotify_body(1, Some(FanotifyInfo { rule_number: 0x2a, subj_trust: 1, obj_trust: 0 }));
    assert_eq!(text(&b), "resp=1 fan_type=1 fan_info=2A subj_trust=1 obj_trust=0");
}

#[test]
fn a_zero_rule_number_still_renders_a_digit() {
    let b = fanotify_body(1, Some(FanotifyInfo::default()));
    assert_eq!(text(&b), "resp=1 fan_type=1 fan_info=0 subj_trust=0 obj_trust=0");
}

#[test]
fn a_syscall_filter_record_names_the_call_the_action_and_the_result() {
    let b = seccomp_body(SeccompEvent {
        tid: 91, signal: 31, action: 0x8000_0000, syscall: 59, arch: 0xc000_003e,
        ip: 0x7f00_1234, errno: 0,
    });
    assert_eq!(text(&b),
        "pid=91 sig=31 arch=c000003e syscall=59 ip=7f001234 code=80000000 res=0");
}

/// A tracer may rewrite the syscall number to a negative value to skip the
/// call; the record must carry that as a signed number.
#[test]
fn a_negative_syscall_number_renders_signed() {
    let b = seccomp_body(SeccompEvent { syscall: -1, ..SeccompEvent::default() });
    let s = text(&b);
    assert!(s.contains(" syscall=-1 "), "{s}");
}

#[test]
fn the_record_bodies_are_free_of_bytes_that_would_split_a_field() {
    for b in [fanotify_body(2, None), seccomp_body(SeccompEvent::default())] {
        let fields: Vec<&[u8]> = b.split(|c| *c == b' ').collect();
        assert!(fields.iter().all(|f| f.contains(&b'=')), "every field is a key=value pair");
    }
}
