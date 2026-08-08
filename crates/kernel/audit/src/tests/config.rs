use super::*;

#[test]
fn a_fresh_configuration_is_off_with_the_default_backlog() {
    let c = Config::default();
    assert_eq!(c, Config::new());
    assert_eq!(c.enabled, AUDIT_OFF);
    assert_eq!(c.failure, AUDIT_FAIL_PRINTK);
    assert_eq!(c.rate_limit, 0);
    assert_eq!(c.backlog_limit, AUDIT_BACKLOG_LIMIT_DEFAULT);
    assert_eq!(c.backlog_wait_time, AUDIT_BACKLOG_WAIT_TIME);
    assert!(!c.locked());
}

#[test]
fn the_enable_state_takes_only_its_three_values() {
    let mut c = Config::new();
    assert_eq!(set(&mut c, Field::Enabled, AUDIT_ON), Ok(()));
    assert_eq!(c.enabled, AUDIT_ON);
    assert_eq!(set(&mut c, Field::Enabled, AUDIT_LOCKED + 1), Err(Errno::Einval));
    assert_eq!(c.enabled, AUDIT_ON, "a rejected value changes nothing");
}

/// Locking is the point of the state: once locked every configuration change
/// is EPERM, including unlocking.
#[test]
fn a_locked_configuration_refuses_every_change() {
    let mut c = Config::new();
    assert_eq!(set(&mut c, Field::Enabled, AUDIT_LOCKED), Ok(()));
    for (f, v) in [(Field::Enabled, AUDIT_ON), (Field::Enabled, AUDIT_OFF),
                   (Field::Failure, AUDIT_FAIL_SILENT), (Field::RateLimit, 5),
                   (Field::BacklogLimit, 5), (Field::BacklogWaitTime, 5)] {
        assert_eq!(set(&mut c, f, v), Err(Errno::Eperm), "{f:?}");
    }
    assert_eq!(c, {
        let mut want = Config::new();
        want.enabled = AUDIT_LOCKED;
        want
    });
}

/// The value check runs before the lock check, so a locked configuration still
/// reports a bad value as a bad value — the client learns its request was
/// malformed rather than that it lacked a permission it would not have needed.
#[test]
fn an_invalid_value_outranks_the_lock() {
    let mut c = Config::new();
    set(&mut c, Field::Enabled, AUDIT_LOCKED).unwrap();
    assert_eq!(set(&mut c, Field::Failure, 3), Err(Errno::Einval));
    assert_eq!(set(&mut c, Field::BacklogWaitTime, AUDIT_BACKLOG_WAIT_TIME_MAX + 1),
        Err(Errno::Einval));
}

#[test]
fn the_failure_mode_takes_only_its_three_values() {
    let mut c = Config::new();
    for v in [AUDIT_FAIL_SILENT, AUDIT_FAIL_PRINTK, AUDIT_FAIL_PANIC] {
        assert_eq!(set(&mut c, Field::Failure, v), Ok(()));
        assert_eq!(c.failure, v);
    }
    assert_eq!(set(&mut c, Field::Failure, 3), Err(Errno::Einval));
    assert_eq!(set(&mut c, Field::Failure, u32::MAX), Err(Errno::Einval));
}

#[test]
fn the_backlog_wait_time_is_bounded() {
    let mut c = Config::new();
    assert_eq!(set(&mut c, Field::BacklogWaitTime, AUDIT_BACKLOG_WAIT_TIME_MAX), Ok(()));
    assert_eq!(set(&mut c, Field::BacklogWaitTime, AUDIT_BACKLOG_WAIT_TIME_MAX + 1),
        Err(Errno::Einval));
    assert_eq!(c.backlog_wait_time, AUDIT_BACKLOG_WAIT_TIME_MAX);
}

/// The limits themselves take any value: zero means unlimited and there is no
/// upper bound to enforce.
#[test]
fn the_two_limits_accept_every_value() {
    let mut c = Config::new();
    for v in [0, 1, u32::MAX] {
        assert_eq!(set(&mut c, Field::RateLimit, v), Ok(()));
        assert_eq!(set(&mut c, Field::BacklogLimit, v), Ok(()));
    }
}

#[test]
fn every_field_reads_back_the_value_it_stored() {
    let mut c = Config::new();
    for (f, v) in [(Field::Enabled, AUDIT_ON), (Field::Failure, AUDIT_FAIL_PANIC),
                   (Field::RateLimit, 11), (Field::BacklogLimit, 12),
                   (Field::BacklogWaitTime, 13)] {
        set(&mut c, f, v).unwrap();
        assert_eq!(f.get(&c), v, "{f:?}");
        assert!(!f.name().is_empty());
    }
}

#[test]
fn the_lost_counter_saturates_rather_than_wrapping() {
    let mut c = Config::new();
    c.lost = u32::MAX - 1;
    c.count_lost();
    c.count_lost();
    c.count_lost();
    assert_eq!(c.lost, u32::MAX, "a wrapped counter would understate the hole");
}

#[test]
fn reading_the_lost_counter_clears_it() {
    let mut c = Config::new();
    c.count_lost();
    c.count_lost();
    assert_eq!(c.take_lost(), 2);
    assert_eq!(c.take_lost(), 0);
    c.backlog_wait_time_actual = 9;
    assert_eq!(c.take_backlog_wait_time_actual(), 9);
    assert_eq!(c.take_backlog_wait_time_actual(), 0);
}

#[test]
fn a_feature_can_be_turned_on_and_off_until_it_is_locked() {
    let mut c = Config::new();
    let bit = feature_to_mask(AUDIT_FEATURE_LOGINUID_IMMUTABLE);
    let req = FeatureRequest { vers: AUDIT_FEATURE_VERSION, mask: bit, features: bit, lock: 0 };
    assert_eq!(apply_features(&mut c, req), Ok(()));
    assert_eq!(c.features & bit, bit);
    assert_eq!(c.feature_lock, 0);
    assert_eq!(apply_features(&mut c, FeatureRequest { features: 0, ..req }), Ok(()));
    assert_eq!(c.features & bit, 0);
}

#[test]
fn a_locked_feature_may_be_re_requested_at_its_current_value_but_not_moved() {
    let mut c = Config::new();
    let bit = feature_to_mask(AUDIT_FEATURE_LOGINUID_IMMUTABLE);
    let on = FeatureRequest { vers: AUDIT_FEATURE_VERSION, mask: bit, features: bit, lock: bit };
    assert_eq!(apply_features(&mut c, on), Ok(()));
    assert_eq!(c.feature_lock & bit, bit);
    assert_eq!(apply_features(&mut c, on), Ok(()), "no change is not a change");
    assert_eq!(apply_features(&mut c, FeatureRequest { features: 0, ..on }), Err(Errno::Eperm));
    assert_eq!(c.features & bit, bit, "the refused request changed nothing");
}

/// Validation runs over the whole request before anything is committed: a
/// request naming a movable feature and a locked one must change neither.
#[test]
fn a_request_touching_a_locked_feature_commits_nothing() {
    let mut c = Config::new();
    let locked = feature_to_mask(AUDIT_FEATURE_LOGINUID_IMMUTABLE);
    let free = feature_to_mask(AUDIT_FEATURE_ONLY_UNSET_LOGINUID);
    apply_features(&mut c, FeatureRequest {
        vers: AUDIT_FEATURE_VERSION, mask: locked, features: locked, lock: locked }).unwrap();
    let both = FeatureRequest {
        vers: AUDIT_FEATURE_VERSION, mask: locked | free, features: free, lock: 0 };
    assert_eq!(apply_features(&mut c, both), Err(Errno::Eperm));
    assert_eq!(c.features & free, 0, "the movable feature was not committed either");
    assert_eq!(c.features & locked, locked);
}

/// A feature outside the mask is untouched even when its bit is set in the
/// value word.
#[test]
fn only_masked_features_are_applied() {
    let mut c = Config::new();
    let a = feature_to_mask(AUDIT_FEATURE_ONLY_UNSET_LOGINUID);
    let b = feature_to_mask(AUDIT_FEATURE_LOGINUID_IMMUTABLE);
    let req = FeatureRequest { vers: AUDIT_FEATURE_VERSION, mask: a, features: a | b, lock: 0 };
    assert_eq!(apply_features(&mut c, req), Ok(()));
    assert_eq!(c.features, a);
}
