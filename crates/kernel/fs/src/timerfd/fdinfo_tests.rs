//! `fdinfo` rendering and the `TFD_IOC_SET_TICKS` state transition.

use alloc::vec::Vec;

use super::fdinfo::render;
use super::ioctl::TFD_IOC_SET_TICKS;
use super::state::TimerfdState;
use super::uapi::Itimerspec;
use vfs::VfsError;

fn text(clockid: u64, ticks: u64, flags: u16, spec: Itimerspec) -> alloc::string::String {
    let mut out = Vec::new();
    render(&mut out, clockid, ticks, flags, spec);
    alloc::string::String::from_utf8(out).unwrap()
}

#[test]
fn fdinfo_renders_five_lines_with_second_nanosecond_pairs() {
    let spec = Itimerspec { interval_ns: 1_500_000_000, value_ns: 2_000_000_003 };
    assert_eq!(text(super::model::CLOCK_MONOTONIC, 7, 0, spec),
        "clockid: 1\nticks: 7\nsettime flags: 00\nit_value: (2, 3)\nit_interval: (1, 500000000)\n");
}

#[test]
fn settime_flags_render_in_octal_with_a_leading_zero() {
    let spec = Itimerspec { interval_ns: 0, value_ns: 0 };
    // TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET = 3.
    assert!(text(0, 0, 3, spec).contains("settime flags: 03\n"));
    assert!(text(0, 0, 1, spec).contains("settime flags: 01\n"));
    assert!(text(0, 0, 0, spec).contains("settime flags: 00\n"));
}

#[test]
fn a_disarmed_timer_renders_zero_pairs() {
    let spec = Itimerspec { interval_ns: 0, value_ns: 0 };
    assert!(text(super::model::CLOCK_REALTIME, 0, 0, spec)
        .ends_with("it_value: (0, 0)\nit_interval: (0, 0)\n"));
}

#[test]
fn settime_records_the_flags_it_armed_with() {
    let mut state = TimerfdState::new(0);
    state.install(0, 0, 100, 0, true, true, 3);
    assert_eq!(state.settime_flags, 3);
    // Re-arming relative clears them again.
    state.install(0, 0, 100, 0, false, false, 0);
    assert_eq!(state.settime_flags, 0);
}

#[test]
fn set_ticks_injects_an_expiration_count_without_disturbing_the_deadline() {
    let mut state = TimerfdState::new(0);
    state.install(0, 0, 100, 10, false, false, 0);
    assert_eq!(state.set_ticks(5), Ok(()));
    assert_eq!(state.ticks, 5);
    assert_eq!(state.expiry_ns, 100, "an injection must not re-arm the timer");
    assert_eq!(state.interval_ns, 10);
}

#[test]
fn set_ticks_reports_a_pending_clock_step_and_consumes_it() {
    let mut state = TimerfdState::new(0);
    state.install(0, 0, 100, 0, true, true, 3);
    assert!(state.note_clock_was_set(1, 0, 0, 0));
    assert!(state.cancel_pending);
    assert_eq!(state.set_ticks(5), Err(VfsError::Ecanceled));
    assert_eq!(state.ticks, 0, "the injection is dropped, not applied");
    assert!(!state.cancel_pending, "the cancellation is reported exactly once");
    assert_eq!(state.set_ticks(5), Ok(()));
    assert_eq!(state.ticks, 5);
}

#[test]
fn the_set_ticks_request_number_is_the_published_encoding() {
    // _IOW('T', 0, __u64): direction 01, size 8, type 'T', nr 0.
    assert_eq!(TFD_IOC_SET_TICKS, 0x4008_5400);
    assert_eq!((TFD_IOC_SET_TICKS >> 30) & 0b11, 1, "write direction");
    assert_eq!((TFD_IOC_SET_TICKS >> 16) & 0x3fff, 8, "one u64 of payload");
    assert_eq!((TFD_IOC_SET_TICKS >> 8) & 0xff, b'T' as u64);
    assert_eq!(TFD_IOC_SET_TICKS & 0xff, 0);
}
