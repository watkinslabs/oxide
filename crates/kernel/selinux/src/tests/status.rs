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
