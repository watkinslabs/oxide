use super::*;
use ipc::win32_menu::track_loop::{classify, LoopAction, VK_ESCAPE, VK_F10, WM_CHAR, WM_KEYDOWN, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_MOUSEMOVE, WM_RBUTTONDBLCLK, WM_RBUTTONUP, WM_SYSCHAR, WM_SYSKEYDOWN};

#[test]
fn the_cancel_request_is_recognised_whatever_its_parameters() {
    assert_eq!(classify(ipc::win32_menu::track::WM_CANCELMODE, 9, 9), LoopAction::Cancel);
}

#[test]
fn pointer_messages_carry_the_point_from_the_message_parameter() {
    let lparam = (10u64 | (20u64 << 16)) as i64;
    assert_eq!(classify(WM_LBUTTONDOWN, 0, lparam), LoopAction::ButtonDown { point: (10, 20), right: false });
    assert_eq!(classify(WM_RBUTTONDBLCLK, 0, lparam), LoopAction::ButtonDown { point: (10, 20), right: true });
    assert_eq!(classify(WM_LBUTTONUP, 0, lparam), LoopAction::ButtonUp { point: (10, 20), right: false });
    assert_eq!(classify(WM_RBUTTONUP, 0, lparam), LoopAction::ButtonUp { point: (10, 20), right: true });
    assert_eq!(classify(WM_MOUSEMOVE, 0, lparam), LoopAction::Move { point: (10, 20) });
    assert_eq!(classify(0x0207, 0, lparam), LoopAction::Pointer);
}

#[test]
fn a_negative_pointer_coordinate_stays_negative() {
    let lparam = ((-5i16 as u16 as u64) | ((-9i16 as u16 as u64) << 16)) as i64;
    assert_eq!(classify(WM_MOUSEMOVE, 0, lparam), LoopAction::Move { point: (-5, -9) });
}

#[test]
fn key_messages_separate_virtual_keys_from_characters() {
    assert_eq!(classify(WM_KEYDOWN, VK_ESCAPE as u64, 0), LoopAction::Key { vk: VK_ESCAPE });
    assert_eq!(classify(WM_SYSKEYDOWN, VK_F10 as u64, 0), LoopAction::Key { vk: VK_F10 });
    assert_eq!(classify(WM_CHAR, 'x' as u64, 0), LoopAction::Char { ch: 'x' as u16 });
    assert_eq!(classify(WM_SYSCHAR, 'x' as u64, 0), LoopAction::Char { ch: 'x' as u16 });
    assert_eq!(classify(0x0101, 0, 0), LoopAction::Other);
}

#[test]
fn everything_outside_the_tracked_ranges_is_dropped_by_the_loop() {
    assert_eq!(classify(0x000f, 0, 0), LoopAction::Other);
    assert_eq!(classify(0x0113, 0, 0), LoopAction::Other);
}

#[test]
fn the_session_remembers_which_window_shows_which_menu() {
    let mut session = MenuSession::new(7);
    session.opened(1, 100);
    session.opened(2, 200);
    assert_eq!(session.window_of(1), Some(100));
    assert_eq!(session.window_of(2), Some(200));
    assert_eq!(session.window_of(3), None);
    assert_eq!(session.innermost_first(), alloc::vec![(2, 200), (1, 100)]);
    assert_eq!(session.closed(2), Some(200));
    assert_eq!(session.closed(2), None);
    assert_eq!(session.closed(1), Some(100));
    assert!(session.innermost_first().is_empty());
}

#[test]
fn the_cancellation_record_carries_only_the_owner_and_the_stop_flag() {
    let mut cancel = MenuCancel { owner: 7, exit: false };
    cancel.exit = true;
    assert_eq!((cancel.owner, cancel.exit), (7, true));
}

#[test]
fn reopening_a_menu_replaces_its_window_rather_than_duplicating_it() {
    let mut session = MenuSession::new(7);
    session.opened(1, 100);
    session.opened(1, 101);
    assert_eq!(session.innermost_first(), alloc::vec![(1, 101)]);
    assert_eq!(session.window_of(1), Some(101));
}
