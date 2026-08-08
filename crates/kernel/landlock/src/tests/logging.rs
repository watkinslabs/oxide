use super::*;

/// A layer enforced with no logging flag reports what THIS execution is
/// refused and goes quiet once the program is replaced.
#[test]
fn the_default_reports_the_same_execution_only() {
    let c = LogConfig::default();
    assert_eq!(c, LogConfig::from_flags(0, true));
    assert_eq!(c.status, LogStatus::Pending);
    assert!(c.reports(true));
    assert!(!c.reports(false));
}

#[test]
fn the_same_exec_flag_turns_off_the_default_reporting() {
    let c = LogConfig::from_flags(RESTRICT_SELF_LOG_SAME_EXEC_OFF | RESTRICT_SELF_LOG_NEW_EXEC_ON,
        true);
    assert!(!c.reports(true));
    assert!(c.reports(false));
    assert_eq!(c.status, LogStatus::Pending);
}

/// Naming both "off" switches at once means the layer reports nothing at all;
/// that is recorded as the status so the denial path stops at one test.
#[test]
fn a_layer_that_reports_in_neither_execution_is_disabled_outright() {
    let c = LogConfig::from_flags(RESTRICT_SELF_LOG_SAME_EXEC_OFF, true);
    assert_eq!(c.status, LogStatus::Disabled);
    assert!(!c.reports(true));
    assert!(!c.reports(false));
}

/// A parent that silenced the layers beneath it wins over whatever the layer
/// asks for itself — that is what makes the switch usable for confining a
/// child that would otherwise turn its own logging back on.
#[test]
fn a_silenced_subdomain_cannot_report_however_it_is_configured() {
    for flags in [0, RESTRICT_SELF_LOG_NEW_EXEC_ON,
                  RESTRICT_SELF_LOG_SAME_EXEC_OFF | RESTRICT_SELF_LOG_NEW_EXEC_ON] {
        let c = LogConfig::from_flags(flags, false);
        assert_eq!(c.status, LogStatus::Disabled, "flags {flags}");
        assert!(!c.reports(true));
        assert!(!c.reports(false));
    }
}

#[test]
fn silencing_subdomains_is_one_way() {
    assert!(subdomains_allowed(true, 0));
    assert!(!subdomains_allowed(true, RESTRICT_SELF_LOG_SUBDOMAINS_OFF));
    assert!(!subdomains_allowed(false, 0), "a child cannot restore what a parent turned off");
    assert!(!subdomains_allowed(false, RESTRICT_SELF_LOG_SUBDOMAINS_OFF));
}

#[test]
fn the_thread_state_packs_the_layer_set_and_the_subdomain_switch() {
    let mut st = 0u32;
    assert_eq!(exec_layers(st), 0);
    assert!(state_allows_subdomains(st));
    st = state_after_restrict(st, 0, Some(0));
    st = state_after_restrict(st, 0, Some(3));
    assert_eq!(exec_layers(st), 0b1001);
    assert!(state_allows_subdomains(st));
    st = state_after_restrict(st, RESTRICT_SELF_LOG_SUBDOMAINS_OFF, None);
    assert!(!state_allows_subdomains(st));
    assert_eq!(exec_layers(st), 0b1001, "the switch did not disturb the layer set");
}

/// The switch survives an enforcement that installs no layer, which is exactly
/// the call shape a launcher uses.
#[test]
fn silencing_subdomains_needs_no_layer_and_is_never_undone() {
    let st = state_after_restrict(0, RESTRICT_SELF_LOG_SUBDOMAINS_OFF, None);
    assert!(!state_allows_subdomains(st));
    let later = state_after_restrict(st, 0, Some(1));
    assert!(!state_allows_subdomains(later));
}

/// A new program enforced no layer, so its denials fall under the new-execution
/// rule; the subdomain switch was a decision about the layers and survives.
#[test]
fn a_new_execution_clears_the_layer_set_but_not_the_switch() {
    let st = state_after_restrict(
        state_after_restrict(0, RESTRICT_SELF_LOG_SUBDOMAINS_OFF, None), 0, Some(2));
    let after = state_after_exec(st);
    assert_eq!(exec_layers(after), 0);
    assert!(!state_allows_subdomains(after));
}

/// A layer level outside the stack cannot corrupt the switch bit.
#[test]
fn an_out_of_range_layer_is_ignored() {
    let st = state_after_restrict(0, 0, Some(MAX_NUM_LAYERS));
    assert_eq!(exec_layers(st), 0);
    assert!(state_allows_subdomains(st));
}

#[test]
fn a_layers_live_state_starts_from_its_configuration() {
    let l = LayerLog::new(LogConfig::default(), DomainDetails::default());
    assert_eq!(l.status(), LogStatus::Pending);
    assert_eq!(l.denials(), 0);
    let d = LayerLog::new(LogConfig::from_flags(RESTRICT_SELF_LOG_SAME_EXEC_OFF, true),
        DomainDetails::default());
    assert_eq!(d.status(), LogStatus::Disabled);
    assert!(!d.reports(true));
}

/// Exactly one caller may describe a layer, so the description record is
/// written once however many denials race.
#[test]
fn only_the_first_claim_describes_a_layer() {
    let l = LayerLog::new(LogConfig::default(), DomainDetails::default());
    assert_eq!(l.claim_description(), LogStatus::Pending);
    assert_eq!(l.claim_description(), LogStatus::Recorded);
    assert_eq!(l.claim_description(), LogStatus::Recorded);
    assert_eq!(l.status(), LogStatus::Recorded);
}

/// A disabled layer is never described, and claiming does not enable it.
#[test]
fn a_disabled_layer_is_never_described() {
    let l = LayerLog::new(LogConfig::from_flags(RESTRICT_SELF_LOG_SAME_EXEC_OFF, true),
        DomainDetails::default());
    assert_eq!(l.claim_description(), LogStatus::Disabled);
    assert_eq!(l.status(), LogStatus::Disabled);
}

/// Denials are counted whatever the reporting decision is: a policy author
/// wants the count even from a layer that was asked to stay quiet.
#[test]
fn denials_are_counted_even_on_a_disabled_layer() {
    let l = LayerLog::new(LogConfig::from_flags(RESTRICT_SELF_LOG_SAME_EXEC_OFF, true),
        DomainDetails::default());
    for _ in 0..5 { l.count_denial(); }
    assert_eq!(l.denials(), 5);
    assert!(!l.reports(true));
}
