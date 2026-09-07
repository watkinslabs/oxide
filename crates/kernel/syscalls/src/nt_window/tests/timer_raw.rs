//! Timer ordinal decode and result encoding.
use super::*;

#[test]
fn each_ordinal_selects_its_message_space() {
    assert_eq!(decode(SET_ORDINAL, [7, 3, 100, 0xaa, 0]), Some(Request::Arm { hwnd: 7, message: WM_TIMER, id: 3, timeout_ms: 100, proc: 0xaa }));
    assert_eq!(decode(SET_SYSTEM_ORDINAL, [7, 3, 100, 0xaa, 0]), Some(Request::Arm { hwnd: 7, message: WM_SYSTIMER, id: 3, timeout_ms: 100, proc: 0 }));
    assert_eq!(decode(KILL_ORDINAL, [7, 3, 0, 0, 0]), Some(Request::Disarm { hwnd: 7, message: WM_TIMER, id: 3 }));
    assert_eq!(decode(KILL_SYSTEM_ORDINAL, [7, 3, 0, 0, 0]), Some(Request::Disarm { hwnd: 7, message: WM_SYSTIMER, id: 3 }));
}

#[test]
fn an_unrelated_ordinal_is_not_claimed() { assert_eq!(decode(0x1234, [0; 5]), None); }

#[test]
fn a_timeout_wider_than_the_abi_field_truncates_before_the_clamp() {
    let Some(Request::Arm { timeout_ms, .. }) = decode(SET_ORDINAL, [7, 3, 0x1_0000_0064, 0, 0]) else { panic!("arm") };
    assert_eq!(timeout_ms, 100);
}

#[test]
fn a_zero_id_reports_success_and_any_other_id_reports_itself() {
    assert_eq!(arm_result(0), 1);
    assert_eq!(arm_result(1), 1);
    assert_eq!(arm_result(0x7fff), 0x7fff);
}
