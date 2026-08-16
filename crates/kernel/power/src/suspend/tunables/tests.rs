use super::*;

#[test]
fn bool_writes_accept_only_zero_and_one() {
    assert_eq!(parse_bool(b"0"), Some(false));
    assert_eq!(parse_bool(b"1"), Some(true));
    assert_eq!(parse_bool(b"0\n"), Some(false));
    assert_eq!(parse_bool(b"1\n"), Some(true));
    for bad in [&b""[..], b"2", b"-1", b"01", b"y", b"true", b" 1", b"1 "] {
        assert_eq!(parse_bool(bad), None, "accepted {bad:?}");
    }
}

#[test]
fn count_writes_parse_unsigned_decimal() {
    assert_eq!(parse_u32(b"0"), Some(0));
    assert_eq!(parse_u32(b"42\n"), Some(42));
    assert_eq!(parse_u32(b"4294967295"), Some(u32::MAX));
}

#[test]
fn count_writes_reject_junk_and_overflow() {
    for bad in [&b""[..], b"\n", b"-1", b"1a", b" 1", b"4294967296", b"99999999999"] {
        assert_eq!(parse_u32(bad), None, "accepted {bad:?}");
    }
}

#[test]
fn a_second_transition_is_refused_while_one_runs() {
    let _g = crate::suspend::test_lock();
    release_transition();
    assert!(!transition_in_progress());
    assert!(try_claim_transition());
    assert!(transition_in_progress());
    assert!(!try_claim_transition(), "two transitions claimed at once");
    release_transition();
    assert!(try_claim_transition());
    release_transition();
}

#[test]
fn the_mem_sleep_selection_round_trips() {
    let _g = crate::suspend::test_lock();
    for s in [SuspendState::ToIdle, SuspendState::Standby, SuspendState::Mem] {
        set_mem_sleep_current(s);
        assert_eq!(mem_sleep_current(), s);
    }
    // `On` is not a mechanism; storing it reads back as the always-available one.
    set_mem_sleep_current(SuspendState::On);
    assert_eq!(mem_sleep_current(), SuspendState::ToIdle);
    set_mem_sleep_current(SuspendState::ToIdle);
}

#[test]
fn the_boolean_tunables_default_the_way_the_reference_does() {
    // A fresh machine syncs before suspending and allows asynchronous device
    // phases; debug messages are off.
    let _g = crate::suspend::test_lock();
    set_sync_on_suspend(true); set_pm_async(true); set_pm_debug_messages(false);
    assert!(sync_on_suspend());
    assert!(pm_async());
    assert!(!pm_debug_messages());
    set_sync_on_suspend(false);
    assert!(!sync_on_suspend());
    set_sync_on_suspend(true);
}
