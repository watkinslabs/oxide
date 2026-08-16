use super::*;
use crate::suspend::ops::PlatformSuspendOps;
use crate::decide::KResult;

fn ok_enter(_s: SuspendState) -> KResult<()> { Ok(()) }
fn valid_mem(s: SuspendState) -> bool { s == SuspendState::Mem }
fn valid_standby(s: SuspendState) -> bool { s == SuspendState::Standby }
fn valid_both(s: SuspendState) -> bool { s == SuspendState::Mem || s == SuspendState::Standby }
fn valid_all(_s: SuspendState) -> bool { true }

fn ops_with(valid: fn(SuspendState) -> bool, enter: bool) -> PlatformSuspendOps {
    let mut o = PlatformSuspendOps::none();
    o.valid = Some(valid);
    if enter { o.enter = Some(ok_enter); }
    o
}

#[test]
fn no_platform_ops_admits_nothing() {
    for s in ENTERABLE { assert!(!valid_state(None, s)); }
}

#[test]
fn valid_without_enter_admits_nothing() {
    let o = ops_with(valid_all, false);
    for s in ENTERABLE { assert!(!valid_state(Some(&o), s), "{s:?} admitted with no enter"); }
}

#[test]
fn enter_without_valid_admits_nothing() {
    let mut o = PlatformSuspendOps::none();
    o.enter = Some(ok_enter);
    for s in ENTERABLE { assert!(!valid_state(Some(&o), s)); }
}

#[test]
fn state_list_always_has_freeze_and_mem() {
    let set = pm_states(None);
    assert!(set.contains(SuspendState::ToIdle));
    assert!(set.contains(SuspendState::Mem));
    assert!(!set.contains(SuspendState::Standby));
}

#[test]
fn standby_listed_only_when_admitted() {
    let o = ops_with(valid_standby, true);
    assert!(pm_states(Some(&o)).contains(SuspendState::Standby));
    let o = ops_with(valid_mem, true);
    assert!(!pm_states(Some(&o)).contains(SuspendState::Standby));
}

#[test]
fn mem_sleep_list_tracks_platform_exactly() {
    assert_eq!(mem_sleep_states(None), StateSet::empty().with(SuspendState::ToIdle));
    let o = ops_with(valid_mem, true);
    assert_eq!(mem_sleep_states(Some(&o)),
        StateSet::empty().with(SuspendState::ToIdle).with(SuspendState::Mem));
    let o = ops_with(valid_both, true);
    assert_eq!(mem_sleep_states(Some(&o)), StateSet::empty()
        .with(SuspendState::ToIdle).with(SuspendState::Standby).with(SuspendState::Mem));
}

#[test]
fn default_mem_sleep_picks_deepest_admitted() {
    assert_eq!(default_mem_sleep(None), SuspendState::ToIdle);
    let o = ops_with(valid_standby, true);
    assert_eq!(default_mem_sleep(Some(&o)), SuspendState::Standby);
    let o = ops_with(valid_both, true);
    assert_eq!(default_mem_sleep(Some(&o)), SuspendState::Mem);
}

#[test]
fn decode_accepts_trailing_newline_and_bare() {
    let set = pm_states(None);
    assert_eq!(decode_state(set, b"freeze"), SuspendState::ToIdle);
    assert_eq!(decode_state(set, b"freeze\n"), SuspendState::ToIdle);
    assert_eq!(decode_state(set, b"mem\n"), SuspendState::Mem);
}

#[test]
fn decode_rejects_unavailable_and_unknown() {
    let set = pm_states(None);
    assert_eq!(decode_state(set, b"standby\n"), SuspendState::On);
    assert_eq!(decode_state(set, b"disk\n"), SuspendState::On);
    assert_eq!(decode_state(set, b""), SuspendState::On);
    // A prefix must not match: `fre` is not `freeze`.
    assert_eq!(decode_state(set, b"fre\n"), SuspendState::On);
    // Nor must a superstring.
    assert_eq!(decode_state(set, b"freezer\n"), SuspendState::On);
}

#[test]
fn decode_uses_the_right_vocabulary() {
    let o = ops_with(valid_mem, true);
    let ms = mem_sleep_states(Some(&o));
    assert_eq!(decode_mem_sleep(ms, b"deep\n"), SuspendState::Mem);
    assert_eq!(decode_mem_sleep(ms, b"s2idle\n"), SuspendState::ToIdle);
    // `mem` is a state label, never a mechanism label.
    assert_eq!(decode_mem_sleep(ms, b"mem\n"), SuspendState::On);
    // and `deep` is a mechanism label, never a state label.
    assert_eq!(decode_state(pm_states(Some(&o)), b"deep\n"), SuspendState::On);
}

#[test]
fn mem_resolves_through_the_selection() {
    assert_eq!(resolve_target(SuspendState::Mem, SuspendState::ToIdle), SuspendState::ToIdle);
    assert_eq!(resolve_target(SuspendState::Mem, SuspendState::Mem), SuspendState::Mem);
    // Every other label is itself, whatever the selection says.
    assert_eq!(resolve_target(SuspendState::ToIdle, SuspendState::Mem), SuspendState::ToIdle);
    assert_eq!(resolve_target(SuspendState::Standby, SuspendState::Mem), SuspendState::Standby);
}

#[test]
fn line_len_stops_at_the_first_newline() {
    assert_eq!(line_len(b"mem\n"), 3);
    assert_eq!(line_len(b"mem"), 3);
    assert_eq!(line_len(b"\n"), 0);
    assert_eq!(line_len(b"a\nb\n"), 1);
}
