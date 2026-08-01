use super::*;
use std::path::PathBuf;

fn rules(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut f = Findings::default();
    let off = vec![false; lines.len()];
    check_magic_errno(&PathBuf::from("crates/kernel/x/src/a.rs"), &lines, &off, &mut f);
    f.items().iter().map(|i| i.msg.clone()).collect()
}

// The shapes `07§5` exists to catch must keep failing after the tightening.
#[test]
fn bare_integer_errno_assignment_fails() {
    assert_eq!(rules("    self.last_errno = 22;").len(), 1);
    assert_eq!(rules("    self.pending_signo = 9;").len(), 1);
}

#[test]
fn bare_integer_signo_initializer_fails() {
    assert_eq!(rules("    SigInfo { signo: 9, code: 0 };").len(), 1);
}

#[test]
fn bare_integer_comparison_fails() {
    assert_eq!(rules("    if info.signo == 17 { reap(); }").len(), 1);
    assert_eq!(rules("    if e.errno != 11 { bail(); }").len(), 1);
}

#[test]
fn typed_constants_pass() {
    assert!(rules("    self.last_errno = Errno::Einval as i32;").is_empty());
    assert!(rules("    ev.signo = Signum::Sigchld as u8;").is_empty());
    assert!(rules("    if info.signo == Signum::Sigchld { reap(); }").is_empty());
    assert!(rules("    let s = nr_slot == NR_PSELECT6;").is_empty());
    assert!(rules("    self.errno = 0;").is_empty());
}

// The rule's only finding in the whole tree was this false positive: `_slot`
// appears in the METHOD NAME, and the `!= 0` belongs to an unrelated bitmask.
#[test]
fn a_marker_inside_an_unrelated_identifier_is_not_the_operand() {
    let src = "    pub fn names_slot(&self, slot: usize) -> bool { self.qname_spec & (1 << slot) != 0 }";
    assert!(rules(src).is_empty(), "{:?}", rules(src));
}

#[test]
fn a_call_result_left_of_the_operator_is_not_the_field() {
    assert!(rules("    if err_slot() == 5 { return; }").is_empty());
    assert!(rules("    if slots[i_slot] == 5 { return; }").is_empty());
}

// Guard against over-tightening: the operand test must still see the field
// through the usual `self.` / `x.` prefixes.
#[test]
fn field_access_is_still_the_operand() {
    assert_eq!(rules("    if self.pending_signo == 9 { }").len(), 1);
    assert_eq!(rules("    if req.sys_slot == 270 { }").len(), 1);
}
