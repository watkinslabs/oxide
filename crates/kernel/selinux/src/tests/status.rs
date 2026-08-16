use super::*;

fn line_value(line: &'static [u8]) -> impl Fn(&[u8]) -> Option<&'static [u8]> {
    move |name: &[u8]| {
        for token in line.split(|b| *b == b' ') {
            if let Some(eq) = token.iter().position(|b| *b == b'=') {
                if &token[..eq] == name { return Some(&token[eq + 1..]); }
            }
        }
        None
    }
}

fn line_flag(line: &'static [u8]) -> impl Fn(&[u8]) -> bool {
    move |name: &[u8]| line.split(|b| *b == b' ').any(|t| t == name)
}

fn parse(line: &'static [u8]) -> BootConfig {
    parse_boot_config(line_value(line), line_flag(line))
}

#[test]
fn absent_parameters_leave_the_module_enabled() {
    let c = parse(b"ro root=/dev/vda1");
    assert!(c.enabled, "a distribution shipping a policy needs the module on by default");
    assert_eq!(c.enforcing, None, "no enforcing= means the mode is not decided at boot");
}

#[test]
fn selinux_zero_disables() {
    assert!(!parse(b"ro selinux=0 quiet").enabled);
}

#[test]
fn selinux_one_enables() {
    assert!(parse(b"selinux=1").enabled);
}

#[test]
fn enforcing_flag_forms() {
    assert_eq!(parse(b"enforcing=1").enforcing, Some(Enforcing::Enforcing));
    assert_eq!(parse(b"enforcing=0").enforcing, Some(Enforcing::Permissive));
    assert_eq!(parse(b"enforcing").enforcing, Some(Enforcing::Enforcing));
}

#[test]
fn enforcing_flag_does_not_imply_enabled_state_change() {
    let c = parse(b"selinux=0 enforcing=1");
    assert!(!c.enabled, "an explicit disable wins over an enforcing request");
    assert_eq!(c.enforcing, Some(Enforcing::Enforcing));
}

#[test]
fn enforcing_round_trips_through_the_control_value() {
    for e in [Enforcing::Permissive, Enforcing::Enforcing] {
        assert_eq!(Enforcing::from_flag(e.as_flag()), e);
    }
    assert_eq!(Enforcing::from_flag(2), Enforcing::Enforcing,
               "any non-zero write means enforce");
}

#[test]
fn only_enforcing_refuses() {
    assert!(Enforcing::Enforcing.refuses());
    assert!(!Enforcing::Permissive.refuses());
}

#[test]
fn state_before_a_policy_load_does_not_consult_policy() {
    let s = SecurityState::new(BootConfig { enabled: true, enforcing: Some(Enforcing::Enforcing) });
    assert!(!s.consults_policy(),
            "there is no policy to consult before the first load; denying here would deny the loader itself");
}

#[test]
fn a_disabled_module_never_consults_policy() {
    let mut s = SecurityState::new(BootConfig { enabled: false, enforcing: None });
    s.note_policy_load();
    assert!(!s.consults_policy());
}

#[test]
fn a_policy_load_makes_the_state_consult_policy_and_bumps_both_counters() {
    let mut s = SecurityState::new(BootConfig::default());
    let (seq, load) = (s.seqno, s.policyload);
    s.note_policy_load();
    assert!(s.consults_policy());
    assert_eq!(s.seqno, seq + 1, "a load must invalidate every cached decision");
    assert_eq!(s.policyload, load + 1);
}

#[test]
fn a_bool_commit_bumps_the_decision_sequence_but_not_the_load_count() {
    let mut s = SecurityState::new(BootConfig::default());
    s.note_policy_load();
    let (seq, load) = (s.seqno, s.policyload);
    s.note_bool_commit();
    assert_eq!(s.seqno, seq + 1, "a bool commit changes decisions, so caches must be invalidated");
    assert_eq!(s.policyload, load);
}

#[test]
fn setting_enforcing_on_a_disabled_module_is_refused() {
    let mut s = SecurityState::new(BootConfig { enabled: false, enforcing: None });
    assert!(s.set_enforcing(Enforcing::Enforcing).is_err());
    assert_eq!(s.enforcing, Enforcing::Permissive);
}

#[test]
fn setting_enforcing_on_an_enabled_module_takes_effect() {
    let mut s = SecurityState::new(BootConfig::default());
    assert!(s.set_enforcing(Enforcing::Enforcing).is_ok());
    assert!(s.enforcing.refuses());
}

#[test]
fn a_boot_without_enforcing_starts_permissive() {
    let s = SecurityState::new(BootConfig { enabled: true, enforcing: None });
    assert_eq!(s.enforcing, Enforcing::Permissive);
}

// The status page's seqlock. The reference increments `status->sequence`
// ONCE before writing the page's fields and ONCE after, so the value is even
// whenever the page is readable and odd only inside the update. Userspace
// reads that word first and, per the reference's own comment, waits while it
// is odd — `libselinux` does so by yielding the CPU in a loop.
//
// Publishing the policy sequence number there instead left it at 1 after a
// single policy load — permanently odd — and PID 1 yielded 5.7 million times
// a second for the rest of the boot. Nothing could observe that: the page is
// rendered from state nobody asserted the parity of.

/// The one invariant: readable means even. Checked at rest and after every
/// kind of update, because one odd value at any point wedges the machine.
#[test]
fn the_status_seqlock_is_even_whenever_the_page_is_readable() {
    let mut s = SecurityState::new(BootConfig::default());
    assert_eq!(s.status_seq % 2, 0, "a page that has never been updated is readable");
    for round in 1..=4 {
        s.note_policy_load();
        assert_eq!(s.status_seq % 2, 0, "readable after policy load {round}");
        s.note_bool_commit();
        assert_eq!(s.status_seq % 2, 0, "readable after boolean commit {round}");
    }
}

/// A single policy load is the case that wedged every boot: it is the first
/// update a real machine performs, and one increment leaves it odd.
#[test]
fn one_policy_load_leaves_the_page_readable() {
    let mut s = SecurityState::new(BootConfig::default());
    s.note_policy_load();
    assert_eq!(s.status_seq % 2, 0, "odd after one load: userspace spins forever here");
    assert_eq!(s.status_seq, STATUS_SEQ_PER_UPDATE, "one update is the reference's two bumps");
}

/// It must still ADVANCE, or a reader caching by sequence never re-reads.
#[test]
fn every_update_advances_the_status_seqlock() {
    let mut s = SecurityState::new(BootConfig::default());
    let start = s.status_seq;
    s.note_policy_load();
    let after_load = s.status_seq;
    assert!(after_load > start, "a policy load must be visible as a change");
    s.note_bool_commit();
    let after_bool = s.status_seq;
    assert!(after_bool > after_load, "a boolean commit must be visible as a change");
    assert!(s.set_enforcing(Enforcing::Enforcing).is_ok());
    assert!(s.status_seq > after_bool, "the page carries the mode, so setenforce updates it");
    assert_eq!(s.status_seq % 2, 0, "readable after setenforce");
}

/// Setting the mode it already has changes nothing, so it is not an update.
#[test]
fn a_setenforce_that_changes_nothing_does_not_advance_the_seqlock() {
    let mut s = SecurityState::new(BootConfig::default());
    let before = s.status_seq;
    assert!(s.set_enforcing(Enforcing::Permissive).is_ok());
    assert_eq!(s.status_seq, before);
}

/// The seqlock is NOT the policy sequence number. They advance on the same
/// events but mean different things, and the bug was publishing one as the
/// other — so pin that they are different values.
#[test]
fn the_status_seqlock_is_not_the_policy_sequence_number() {
    let mut s = SecurityState::new(BootConfig::default());
    s.note_policy_load();
    assert_eq!(s.seqno, 1, "the policy sequence counts updates one at a time");
    assert_ne!(s.status_seq, s.seqno, "the page's seqlock is a different counter");
}
