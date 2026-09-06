use super::*;
use syscall::{nt::NtService, SyscallArgs};

fn saved(tid: u64, pointer: u64, raw: bool) -> Retrieval {
    Retrieval { tid, raw, call: NtCall { service: NtService::GetMessage,
        args: SyscallArgs { a0: pointer, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 } } }
}

#[test]
fn nested_retrieval_preserves_original_call_and_convention_per_thread() {
    let mut stack = Vec::new();
    for value in [saved(1, 10, true), saved(2, 20, false), saved(1, 30, false)] { assert!(push(&mut stack, value)); }
    assert_eq!(pop(&mut stack, 1), Some(saved(1, 30, false)));
    assert_eq!(pop(&mut stack, 1), Some(saved(1, 10, true)));
    assert_eq!(pop(&mut stack, 1), None);
    assert_eq!(pop(&mut stack, 2), Some(saved(2, 20, false)));
}

#[test]
fn bounded_admission_never_overwrites_outer_retrieval() {
    let mut stack = Vec::new();
    assert!(!push(&mut stack, saved(0, 0, false)));
    for index in 0..MAX_RETRIEVALS { assert!(push(&mut stack, saved(1, index as u64, true))); }
    let before = stack.clone();
    assert!(!push(&mut stack, saved(1, 999, false)));
    assert_eq!(stack, before);
}

#[test]
fn quit_error_and_callback_pending_are_not_successful_normal_messages() {
    assert_eq!(raw_result(true, 0, Some(WM_QUIT)), 0);
    assert_eq!(raw_result(true, 0, Some(0x100)), 1);
    assert_eq!(raw_result(true, 0, None), ERROR);
    assert_eq!(raw_result(true, 0xc0000008, Some(0x100)), ERROR);
    assert_eq!(raw_result(false, 0x8000001a, None), 0);
    assert_eq!(raw_result(false, 0, Some(WM_QUIT)), 1);
    for get in [false, true] { assert_eq!(raw_result(get, STATUS_PENDING, None), STATUS_PENDING); }
}

#[test]
fn thread_exit_cancels_all_nested_retrievals_without_touching_peer() {
    let mut stack = Vec::new();
    for value in [saved(1, 10, true), saved(2, 20, false), saved(1, 30, false)] { assert!(push(&mut stack, value)); }
    cancel_thread(&mut stack, 1);
    assert_eq!(pop(&mut stack, 1), None);
    assert_eq!(pop(&mut stack, 2), Some(saved(2, 20, false)));
}
