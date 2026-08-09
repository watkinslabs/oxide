// `IORING_REGISTER_NAPI` argument ladder, tracking-mode rules and the
// busy-poll window.

use super::*;
use alloc::vec::Vec;

fn reg(busy_poll_to: u32, prefer: u8, op_param: u32) -> Napi {
    Napi { busy_poll_to, prefer_busy_poll: prefer, opcode: IO_URING_NAPI_REGISTER_OP,
           pad: [0; 2], op_param, resv: 0 }
}

#[test]
fn the_wire_struct_round_trips() {
    let n = Napi { busy_poll_to: 50, prefer_busy_poll: 1, opcode: IO_URING_NAPI_STATIC_ADD_ID,
                   pad: [0; 2], op_param: 42, resv: 0 };
    assert_eq!(Napi::from_bytes(&n.to_bytes()), n);
    assert_eq!(NAPI_BYTES, 16);
}

#[test]
fn reserved_fields_must_be_zero() {
    let mut n = reg(10, 0, IO_URING_NAPI_TRACKING_STATIC);
    n.pad = [1, 0];
    assert_eq!(admit_napi(&n), Err(Errno::Einval));
    let mut n = reg(10, 0, IO_URING_NAPI_TRACKING_STATIC);
    n.resv = 1;
    assert_eq!(admit_napi(&n), Err(Errno::Einval));
    assert_eq!(admit_napi(&reg(10, 0, IO_URING_NAPI_TRACKING_STATIC)), Ok(()));
}

#[test]
fn a_fresh_ring_does_not_busy_poll() {
    let st = NapiState::inactive();
    assert_eq!(st.track_mode, IO_URING_NAPI_TRACKING_INACTIVE);
    assert!(!busy_poll_wanted(&st, 4), "no window means no spinning");
}

#[test]
fn only_the_two_defined_tracking_modes_are_accepted() {
    let cur = NapiState::inactive();
    for mode in [IO_URING_NAPI_TRACKING_DYNAMIC, IO_URING_NAPI_TRACKING_STATIC] {
        assert!(napi_action(&reg(1, 0, mode), &cur).is_ok(), "mode {mode}");
    }
    for mode in [2u32, 7, IO_URING_NAPI_TRACKING_INACTIVE] {
        assert_eq!(napi_action(&reg(1, 0, mode), &cur), Err(Errno::Einval), "mode {mode}");
    }
}

#[test]
fn an_unknown_napi_opcode_is_einval() {
    let mut n = reg(1, 0, IO_URING_NAPI_TRACKING_STATIC);
    n.opcode = 3;
    assert_eq!(napi_action(&n, &NapiState::inactive()), Err(Errno::Einval));
}

#[test]
fn an_oversized_window_is_clamped_not_refused() {
    let cur = NapiState::inactive();
    let got = napi_action(&reg(u32::MAX, 1, IO_URING_NAPI_TRACKING_STATIC), &cur);
    let want = NapiState {
        busy_poll_dt_ns: NAPI_BUSY_POLL_MAX_US as u64 * NSEC_PER_USEC,
        prefer_busy_poll: true, track_mode: IO_URING_NAPI_TRACKING_STATIC,
    };
    assert_eq!(got, Ok(NapiAction::SetMode(want)));
}

#[test]
fn the_window_is_microseconds_in_and_microseconds_back_out() {
    let cur = NapiState::inactive();
    let NapiAction::SetMode(st) = napi_action(&reg(250, 0, IO_URING_NAPI_TRACKING_DYNAMIC), &cur)
        .expect("valid") else { panic!("expected a mode change") };
    assert_eq!(st.busy_poll_dt_ns, 250_000);
    assert_eq!(st.to_wire().busy_poll_to, 250);
    assert_eq!(st.to_wire().op_param, IO_URING_NAPI_TRACKING_DYNAMIC,
        "the write-back reports the tracking mode in op_param");
}

#[test]
fn identifier_edits_need_static_tracking() {
    let mut n = reg(0, 0, MIN_NAPI_ID);
    n.opcode = IO_URING_NAPI_STATIC_ADD_ID;
    for mode in [IO_URING_NAPI_TRACKING_INACTIVE, IO_URING_NAPI_TRACKING_DYNAMIC] {
        let cur = NapiState { track_mode: mode, ..NapiState::inactive() };
        assert_eq!(napi_action(&n, &cur), Err(Errno::Einval), "mode {mode}");
    }
    let cur = NapiState { track_mode: IO_URING_NAPI_TRACKING_STATIC, ..NapiState::inactive() };
    assert_eq!(napi_action(&n, &cur), Ok(NapiAction::AddId(MIN_NAPI_ID)));
    n.opcode = IO_URING_NAPI_STATIC_DEL_ID;
    assert_eq!(napi_action(&n, &cur), Ok(NapiAction::DelId(MIN_NAPI_ID)));
}

#[test]
fn reserved_queue_identifiers_are_refused() {
    let mut ids: Vec<u32> = Vec::new();
    for id in 0..MIN_NAPI_ID {
        assert_eq!(add_id(&mut ids, id), Err(Errno::Einval), "id {id}");
        assert_eq!(del_id(&mut ids, id), Err(Errno::Einval), "id {id}");
    }
    assert!(ids.is_empty());
}

#[test]
fn adding_a_tracked_identifier_twice_is_eexist_and_removing_an_absent_one_is_enoent() {
    let mut ids: Vec<u32> = Vec::new();
    assert_eq!(add_id(&mut ids, 11), Ok(()));
    assert_eq!(add_id(&mut ids, 11), Err(Errno::Eexist));
    assert_eq!(ids.len(), 1, "a refused add must not have duplicated the entry");
    assert_eq!(del_id(&mut ids, 12), Err(Errno::Enoent));
    assert_eq!(del_id(&mut ids, 11), Ok(()));
    assert!(ids.is_empty());
    assert_eq!(del_id(&mut ids, 11), Err(Errno::Enoent));
}

#[test]
fn an_empty_identifier_list_polls_nothing_whichever_mode_is_set() {
    for mode in [IO_URING_NAPI_TRACKING_STATIC, IO_URING_NAPI_TRACKING_DYNAMIC] {
        let st = NapiState { busy_poll_dt_ns: 1_000, prefer_busy_poll: false, track_mode: mode };
        assert!(!busy_poll_wanted(&st, 0), "mode {mode} with no identifiers");
        assert!(busy_poll_wanted(&st, 1), "mode {mode} with one identifier");
    }
}

#[test]
fn a_zero_window_polls_nothing_even_with_identifiers_tracked() {
    let st = NapiState { busy_poll_dt_ns: 0, prefer_busy_poll: false,
                         track_mode: IO_URING_NAPI_TRACKING_STATIC };
    assert!(!busy_poll_wanted(&st, 3));
}

#[test]
fn the_spin_window_never_outlives_the_waits_own_deadline() {
    let st = NapiState { busy_poll_dt_ns: 1_000, prefer_busy_poll: false,
                         track_mode: IO_URING_NAPI_TRACKING_STATIC };
    // No deadline: the whole window is available.
    assert_eq!(busy_poll_until(100, &st, 0), 1_100);
    // A nearer deadline wins, so a timed wait is not extended by spinning.
    assert_eq!(busy_poll_until(100, &st, 500), 500);
    // A later deadline leaves the window as the limit.
    assert_eq!(busy_poll_until(100, &st, 9_000), 1_100);
}

#[test]
fn the_register_ladder_bounds_both_napi_opcodes() {
    use crate::io_uring_abi::register_op::*;
    assert_eq!(decode(IORING_REGISTER_NAPI, 3, 0x1000, 1).map(|r| r.op),
               Ok(RegisterOp::Napi { arg: 0x1000 }));
    assert_eq!(decode(IORING_REGISTER_NAPI, 3, 0, 1).err(), Some(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_NAPI, 3, 0x1000, 2).err(), Some(Errno::Einval));
    // The unregister form accepts a null pointer — it means "do not report the
    // old settings" — but still demands exactly one record.
    assert_eq!(decode(IORING_UNREGISTER_NAPI, 3, 0, 1).map(|r| r.op),
               Ok(RegisterOp::UnregisterNapi { arg: 0 }));
    assert_eq!(decode(IORING_UNREGISTER_NAPI, 3, 0x1000, 0).err(), Some(Errno::Einval));
    // Neither is a blind form.
    assert_eq!(decode(IORING_REGISTER_NAPI, -1, 0x1000, 1).err(), Some(Errno::Einval));
    assert_eq!(decode(IORING_UNREGISTER_NAPI, -1, 0, 1).err(), Some(Errno::Einval));
}
