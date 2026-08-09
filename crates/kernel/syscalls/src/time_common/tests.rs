use super::*;
use namespace_identity::NamespaceKind;

fn owner() -> NamespaceRef {
    let owner = namespace_identity::allocate(
        NamespaceKind::Time,
        namespace_identity::initial(NamespaceKind::User),
        None,
    )
    .unwrap();
    nscg::time_ns::clone_from(
        &owner,
        &namespace_identity::initial(NamespaceKind::Time),
    )
    .unwrap();
    nscg::time_ns::set_offsets(
        &owner,
        &[
            nscg::time_ns::TimeNsUpdate {
                clock: TimeNsClock::Monotonic,
                offset: nscg::time_ns::TimeOffset::new(2, 0).unwrap(),
                host_ns: 10_000_000_000,
            },
            nscg::time_ns::TimeNsUpdate {
                clock: TimeNsClock::Boottime,
                offset: nscg::time_ns::TimeOffset::new(5, 0).unwrap(),
                host_ns: 10_000_000_000,
            },
        ],
    )
    .unwrap();
    owner
}

#[test]
fn linux_time_namespace_clock_classes_apply_exact_offsets() {
    let owner = owner();
    for clock in [CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_MONOTONIC_COARSE] {
        assert_eq!(
            namespace_clock_ns(&owner, clock, 10_000_000_000).unwrap(),
            12_000_000_000,
        );
    }
    for clock in [CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM] {
        assert_eq!(
            namespace_clock_ns(&owner, clock, 10_000_000_000).unwrap(),
            15_000_000_000,
        );
    }
    for clock in [
        CLOCK_REALTIME,
        CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID,
        CLOCK_REALTIME_COARSE,
        CLOCK_REALTIME_ALARM,
    ] {
        assert_eq!(
            namespace_clock_ns(&owner, clock, 10_000_000_000).unwrap(),
            10_000_000_000,
        );
    }
}

#[test]
fn absolute_namespace_deadlines_convert_only_virtualized_clocks() {
    let owner = owner();
    assert_eq!(
        namespace_absolute_to_host(&owner, CLOCK_MONOTONIC, 12_000_000_000).unwrap(),
        10_000_000_000,
    );
    assert_eq!(
        namespace_absolute_to_host(&owner, CLOCK_MONOTONIC_COARSE, 12_000_000_000).unwrap(),
        10_000_000_000,
    );
    assert_eq!(
        namespace_absolute_to_host(&owner, CLOCK_BOOTTIME, 15_000_000_000).unwrap(),
        10_000_000_000,
    );
    assert_eq!(
        namespace_absolute_to_host(&owner, CLOCK_BOOTTIME_ALARM, 15_000_000_000).unwrap(),
        10_000_000_000,
    );
    assert_eq!(
        namespace_absolute_to_host(&owner, CLOCK_MONOTONIC_RAW, 12_000_000_000).unwrap(),
        12_000_000_000,
    );
    assert_eq!(
        namespace_absolute_to_host(&owner, CLOCK_REALTIME, 12_000_000_000).unwrap(),
        12_000_000_000,
    );
    assert_eq!(
        namespace_absolute_to_host(&owner, CLOCK_PROCESS_CPUTIME_ID, 12_000_000_000).unwrap(),
        12_000_000_000,
    );
    assert_eq!(
        namespace_sleep_target_to_host(&owner, CLOCK_MONOTONIC, false, 12_000_000_000)
            .unwrap(),
        12_000_000_000,
        "relative duration must not receive or remove namespace offset",
    );
}

#[test]
fn known_clock_set_rejects_unknown_ids() {
    for clock in [
        CLOCK_REALTIME,
        CLOCK_MONOTONIC,
        CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID,
        CLOCK_MONOTONIC_RAW,
        CLOCK_REALTIME_COARSE,
        CLOCK_MONOTONIC_COARSE,
        CLOCK_BOOTTIME,
        CLOCK_REALTIME_ALARM,
        CLOCK_BOOTTIME_ALARM,
        CLOCK_TAI,
    ] {
        assert!(clock_id_known(clock));
    }
    assert!(!clock_id_known(u64::MAX), "a sign-extended negative id is not a static slot");
    assert!(!clock_id_known(10), "CLOCK_SGI_CYCLE slot is NULL in posix_clocks[]");
    assert!(!clock_id_known(12));
    for clock in [
        CLOCK_REALTIME,
        CLOCK_MONOTONIC,
        CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_BOOTTIME,
        CLOCK_REALTIME_ALARM,
        CLOCK_BOOTTIME_ALARM,
        CLOCK_TAI,
    ] {
        assert!(clock_nanosleep_supported(clock));
    }
    for clock in [
        CLOCK_THREAD_CPUTIME_ID,
        CLOCK_MONOTONIC_RAW,
        CLOCK_REALTIME_COARSE,
        CLOCK_MONOTONIC_COARSE,
    ] {
        assert!(!clock_nanosleep_supported(clock));
    }
    assert!(clock_is_alarm(CLOCK_REALTIME_ALARM));
    assert!(clock_is_alarm(CLOCK_BOOTTIME_ALARM));
    assert!(!clock_is_alarm(CLOCK_BOOTTIME));
}

/// `struct timespec` is `tv_sec` then `tv_nsec`, both 64-bit, in native byte
/// order. Getting the halves the wrong way round turns a one-second timeout
/// into a one-nanosecond one, which reads as a spurious wakeup rather than as
/// a decode bug.
#[test]
fn a_timespec_decodes_seconds_then_nanoseconds() {
    let mut raw = [0u8; TIMESPEC_BYTES];
    raw[..8].copy_from_slice(&7i64.to_ne_bytes());
    raw[8..].copy_from_slice(&123_456_789i64.to_ne_bytes());
    assert_eq!(decode_timespec(&raw), (7, 123_456_789));
}

/// Negative fields survive the decode unchanged: rejecting them is the
/// caller's rule (`timespec_to_ns`), not the reader's, and a reader that
/// clamped here would hide an EINVAL the caller owes.
#[test]
fn a_timespec_decode_preserves_negative_fields() {
    let mut raw = [0u8; TIMESPEC_BYTES];
    raw[..8].copy_from_slice(&(-1i64).to_ne_bytes());
    raw[8..].copy_from_slice(&(-2i64).to_ne_bytes());
    assert_eq!(decode_timespec(&raw), (-1, -2));
    assert!(syscall::time::timespec_to_ns(-1, -2).is_err(), "the caller rejects what the reader preserved");
}

/// The wire size is what the copy asks the exception-table reader for. If it
/// drifted from the structure, the read would either truncate or overrun.
#[test]
fn the_timespec_wire_size_is_two_64_bit_fields() {
    assert_eq!(TIMESPEC_BYTES, 2 * core::mem::size_of::<i64>());
}
