use alloc::vec;
use alloc::vec::Vec;
use super::ladder::*;
use super::uapi::*;
use super::super::{HTCLIENT, WM_SETCURSOR};

const CHILD: u32 = 0x31;
const ROOT: u32 = 0x11;
const PARENT: u32 = 0x21;
const HTCAPTION: i32 = 2;

fn context() -> LadderContext {
    LadderContext { hwnd: CHILD, hit_test: HTCLIENT, origin: WM_LBUTTONDOWN, button_down: true,
        active: None, root: ROOT, root_style: WS_POPUP, notify: Vec::new() }
}

fn notify_call() -> ProcCall {
    ProcCall { hwnd: PARENT, message: WM_PARENTNOTIFY, wparam: WM_LBUTTONDOWN as u64, lparam: make_point(3, 4) }
}

fn set_cursor() -> LadderStep {
    LadderStep::Send(ProcCall { hwnd: CHILD, message: WM_SETCURSOR, wparam: CHILD as u64,
        lparam: make_hit_param(HTCLIENT, WM_LBUTTONDOWN) })
}

fn mouse_activate() -> LadderStep {
    LadderStep::Send(ProcCall { hwnd: CHILD, message: WM_MOUSEACTIVATE, wparam: ROOT as u64,
        lparam: make_hit_param(HTCLIENT, WM_LBUTTONDOWN) })
}

/// Drive the ladder to the end, answering each `Send` from `answers` in order
/// and each `Activate` with `activated`; report every step it took.
fn run(ctx: LadderContext, answers: &[u64], activated: bool) -> (Vec<LadderStep>, bool) {
    let mut ladder = Ladder::new(ctx);
    let mut steps = Vec::new();
    let mut sent = 0;
    for _ in 0..16 {
        let step = ladder.next();
        steps.push(step);
        match step {
            LadderStep::Send(_) => { ladder.call_result(Ok(answers.get(sent).copied().unwrap_or(0))); sent += 1; }
            LadderStep::Activate(_) => ladder.call_result(Ok(activated as u64)),
            LadderStep::Done { eat } => return (steps, eat),
        }
    }
    panic!("ladder did not finish")
}

#[test]
fn a_click_on_an_inactive_window_notifies_the_parents_then_asks_about_activation() {
    let ctx = LadderContext { notify: vec![notify_call()], ..context() };
    let (steps, eat) = run(ctx, &[0, MA_ACTIVATE, 0], true);
    assert_eq!(steps, vec![LadderStep::Send(notify_call()), mouse_activate(), LadderStep::Activate(ROOT),
        set_cursor(), LadderStep::Done { eat: false }]);
    assert!(!eat);
}

#[test]
fn each_activation_code_decides_the_foreground_and_whether_the_click_survives() {
    for (code, activates, eaten) in [(MA_ACTIVATE, true, false), (0, true, false), (MA_ACTIVATEANDEAT, true, true),
        (MA_NOACTIVATE, false, false), (MA_NOACTIVATEANDEAT, false, true), (0x1234, false, false)] {
        let (steps, eat) = run(context(), &[code], true);
        assert_eq!(eat, eaten, "code {code:#x}");
        assert_eq!(steps.contains(&LadderStep::Activate(ROOT)), activates, "code {code:#x}");
        // The cursor is set whatever the answer was, and it is the last call.
        assert_eq!(steps[steps.len() - 2], set_cursor(), "code {code:#x}");
    }
}

#[test]
fn a_refused_foreground_change_eats_the_click_even_without_an_eat_code() {
    let (steps, eat) = run(context(), &[MA_ACTIVATE], false);
    assert!(steps.contains(&LadderStep::Activate(ROOT)));
    assert!(eat);
}

#[test]
fn a_click_on_the_active_window_or_a_pure_child_root_asks_nothing() {
    let already = LadderContext { active: Some(CHILD), ..context() };
    assert_eq!(run(already, &[], true).0, vec![set_cursor(), LadderStep::Done { eat: false }]);
    let child_root = LadderContext { root_style: WS_CHILD, ..context() };
    assert_eq!(run(child_root, &[], true).0, vec![set_cursor(), LadderStep::Done { eat: false }]);
    // A root that is both a child and a popup still activates.
    let popup_child = LadderContext { root_style: WS_CHILD | WS_POPUP, ..context() };
    assert!(run(popup_child, &[MA_ACTIVATE], true).0.contains(&LadderStep::Activate(ROOT)));
}

#[test]
fn a_pointer_message_that_is_not_a_button_down_only_sets_the_cursor() {
    let moved = LadderContext { button_down: false, origin: WM_MOUSEMOVE, notify: vec![notify_call()], ..context() };
    let (steps, eat) = run(moved, &[], true);
    assert_eq!(steps, vec![LadderStep::Send(ProcCall { hwnd: CHILD, message: WM_SETCURSOR, wparam: CHILD as u64,
        lparam: make_hit_param(HTCLIENT, WM_MOUSEMOVE) }), LadderStep::Done { eat: false }]);
    assert!(!eat);
}

#[test]
fn the_whole_parent_chain_is_notified_before_activation_is_decided() {
    let outer = ProcCall { hwnd: ROOT, message: WM_PARENTNOTIFY, wparam: WM_LBUTTONDOWN as u64, lparam: make_point(9, 9) };
    let ctx = LadderContext { notify: vec![notify_call(), outer], ..context() };
    let (steps, _) = run(ctx, &[0, 0, MA_NOACTIVATE], true);
    assert_eq!(&steps[..3], &[LadderStep::Send(notify_call()), LadderStep::Send(outer), mouse_activate()]);
}

#[test]
fn a_nonclient_click_reports_the_hit_code_and_the_client_message_number() {
    let ctx = LadderContext { hit_test: HTCAPTION, ..context() };
    let (steps, _) = run(ctx, &[MA_NOACTIVATE], true);
    assert_eq!(steps[0], LadderStep::Send(ProcCall { hwnd: CHILD, message: WM_MOUSEACTIVATE, wparam: ROOT as u64,
        lparam: make_hit_param(HTCAPTION, WM_LBUTTONDOWN) }));
    assert_eq!(steps[1], LadderStep::Send(ProcCall { hwnd: CHILD, message: WM_SETCURSOR, wparam: CHILD as u64,
        lparam: make_hit_param(HTCAPTION, WM_LBUTTONDOWN) }));
}

#[test]
fn a_window_procedure_that_could_not_be_entered_reads_as_an_unhandled_answer() {
    let mut ladder = Ladder::new(context());
    assert_eq!(ladder.next(), mouse_activate());
    ladder.call_result(Err(()));
    assert_eq!(ladder.next(), LadderStep::Activate(ROOT));
}

#[test]
fn a_single_call_ladder_makes_that_call_and_ends() {
    let call = ProcCall { hwnd: CHILD, message: WM_APPCOMMAND, wparam: CHILD as u64, lparam: 7 };
    let mut ladder = Ladder::single(call);
    assert_eq!(ladder.next(), LadderStep::Send(call));
    ladder.call_result(Ok(1));
    assert_eq!(ladder.next(), LadderStep::Done { eat: false });
}
