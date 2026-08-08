use super::*;
use alloc::string::ToString;

// The global is process-wide; every test that writes it restores the default.
fn with_default<T>(f: impl FnOnce() -> T) -> T {
    let out = f();
    set_kmsg_bytes(DEFAULT_KMSG_BYTES);
    out
}

#[test]
fn the_table_declares_exactly_one_byte_count() {
    assert_eq!(PSTORE_PARAMS.len(), 1);
    assert_eq!(PSTORE_PARAMS[0].name, "kmsg_bytes");
    assert_eq!(PSTORE_PARAMS[0].ty, FsParamType::U32);
}

#[test]
fn a_valid_value_is_taken() {
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=4096", &[]), Some(4096));
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=0x400", &[]), Some(1024));
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=0", &[]), Some(0));
}

#[test]
fn an_invalid_value_is_swallowed_not_refused() {
    // This is the behaviour that separates pstore from every other type
    // registered here: the mount SUCCEEDS and simply changes nothing.
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=notanumber", &[]), None);
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=-1", &[]), None);
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=99999999999999", &[]), None);
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=", &[]), None);
    // A bare word where a value is required is the same negative answer.
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes", &[]), None);
}

#[test]
fn an_unknown_key_is_swallowed() {
    assert_eq!(kmsg_bytes_for_mount("nosuchoption=3", &[]), None);
    assert_eq!(kmsg_bytes_for_mount("uid=0,gid=0,mode=700", &[]), None);
}

#[test]
fn a_good_value_survives_bad_company() {
    assert_eq!(kmsg_bytes_for_mount("junk,kmsg_bytes=64,more=x", &[]), Some(64));
    // Last valid wins, as a repeated parameter does in the reference.
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=64,kmsg_bytes=128", &[]), Some(128));
    assert_eq!(kmsg_bytes_for_mount("kmsg_bytes=64,kmsg_bytes=bad", &[]), Some(64));
}

#[test]
fn a_pinned_parameter_is_swallowed_too() {
    // A descriptor or path value on a numeric option is the wrong shape; the
    // reference drops it and mounts anyway.
    let pinned = [FsParameter::path("kmsg_bytes", "/tmp/x")];
    assert_eq!(kmsg_bytes_for_mount("", &pinned), None);
    let pinned = [FsParameter::string("kmsg_bytes", "512")];
    assert_eq!(kmsg_bytes_for_mount("", &pinned), Some(512));
}

#[test]
fn the_live_bound_round_trips() {
    with_default(|| {
        assert_eq!(kmsg_bytes(), DEFAULT_KMSG_BYTES);
        set_kmsg_bytes(777);
        assert_eq!(kmsg_bytes(), 777);
    });
}

#[test]
fn the_window_is_the_newest_bytes_the_bound_allows() {
    // Bound below what is logged: the tail is taken.
    assert_eq!(capture_window(10_000, 1000, 1 << 20), (9000, 1000));
    // Bound above what is logged: everything is taken.
    assert_eq!(capture_window(500, 10_240, 1 << 20), (0, 500));
    // A smaller bound really does yield a smaller record — the whole point
    // of the option.
    let (_, big) = capture_window(10_000, 4096, 1 << 20);
    let (_, small) = capture_window(10_000, 64, 1 << 20);
    assert!(small < big);
    assert_eq!(small, 64);
}

#[test]
fn the_zone_bounds_the_window_when_it_is_smaller() {
    let total = 1usize << 20;
    assert_eq!(capture_window(total, 10_240, 512), (total - 512, 512));
}

#[test]
fn a_zero_bound_captures_nothing() {
    assert_eq!(capture_window(10_000, 0, 4096), (10_000, 0));
}

#[test]
fn the_option_is_shown_only_when_it_differs_from_the_default() {
    with_default(|| {
        assert_eq!(show_options(), "".to_string());
        set_kmsg_bytes(2048);
        assert_eq!(show_options(), ",kmsg_bytes=2048".to_string());
        set_kmsg_bytes(0);
        assert_eq!(show_options(), ",kmsg_bytes=0".to_string());
    });
}
