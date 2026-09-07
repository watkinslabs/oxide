use super::mouse::*;
use super::uapi::*;
use super::super::{MessageFilter, WinMessage, WindowId, HTCLIENT, HTERROR, HTNOWHERE};

const WINDOW: u32 = 0x21;
const HTCAPTION: i32 = 2;

fn ctx() -> MouseContext {
    MouseContext { hit_test: HTCLIENT, captured: false, modal: false, class_dbl_clks: false,
        double_click_ms: 500, double_click_width: 4, double_click_height: 4, time_ms: 1_000,
        remove: true, filter: range(0, u32::MAX) }
}

/// The filter a retrieval naming both ends of a range builds.
fn range(first: u32, last: u32) -> MessageFilter { MessageFilter { hwnd: None, first, last } }

fn click(message: u32, x: i32, y: i32) -> WinMessage {
    WinMessage { hwnd: WindowId::from_raw(WINDOW), message, wparam: 1, lparam: make_point(x, y) }
}

#[test]
fn a_removed_button_down_runs_the_ladder_and_a_peek_does_not() {
    let mut context = ctx();
    assert_eq!(prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context).outcome, MouseOutcome::Ladder);
    context.remove = false;
    assert_eq!(prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context).outcome, MouseOutcome::Deliver);
}

#[test]
fn a_captured_pointer_skips_the_ladder_and_a_filtered_message_is_dropped() {
    let mut context = ctx();
    context.captured = true;
    assert_eq!(prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context).outcome, MouseOutcome::Deliver);
    context.captured = false;
    context.filter = range(WM_KEYFIRST, WM_KEYLAST);
    let prepared = prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context);
    assert_eq!(prepared.outcome, MouseOutcome::Filtered);
    // A message the caller never asked for must not become the first half of
    // a double click either.
    assert_eq!(prepared.click, ClickUpdate::Keep);
}

#[test]
fn an_error_or_nowhere_hit_only_sets_the_cursor() {
    let mut context = ctx();
    for hit in [HTERROR, HTNOWHERE] {
        context.hit_test = hit;
        assert_eq!(prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context).outcome, MouseOutcome::ErrorCursor);
    }
}

#[test]
fn a_nonclient_hit_renumbers_the_message_and_reports_the_hit_code() {
    let mut context = ctx();
    context.hit_test = HTCAPTION;
    let prepared = prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context);
    assert_eq!(prepared.message.message, WM_LBUTTONDOWN - (WM_MOUSEMOVE - WM_NCMOUSEMOVE));
    assert_eq!(prepared.message.wparam, HTCAPTION as u64);
    assert_eq!(prepared.origin, WM_LBUTTONDOWN);
    // The wheel has no nonclient form and keeps its button state.
    let wheel = prepare(click(WM_MOUSEWHEEL, 3, 4), None, &context);
    assert_eq!(wheel.message.message, WM_MOUSEWHEEL);
    assert_eq!(wheel.message.wparam, 1);
}

#[test]
fn a_second_click_becomes_a_double_click_only_for_a_class_that_asked() {
    let mut context = ctx();
    let first = prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context);
    let ClickUpdate::Store(record) = first.click else { panic!("first click was not remembered") };
    context.time_ms = 1_100;
    // No CS_DBLCLKS over the client area: still a plain button down, and the
    // click is remembered afresh.
    let plain = prepare(click(WM_LBUTTONDOWN, 3, 4), Some(record), &context);
    assert_eq!(plain.message.message, WM_LBUTTONDOWN);
    assert!(matches!(plain.click, ClickUpdate::Store(_)));
    context.class_dbl_clks = true;
    let doubled = prepare(click(WM_LBUTTONDOWN, 3, 4), Some(record), &context);
    assert_eq!(doubled.message.message, WM_LBUTTONDBLCLK);
    assert_eq!(doubled.click, ClickUpdate::Clear);
}

#[test]
fn menu_mode_and_a_nonclient_hit_make_every_click_eligible() {
    let mut context = ctx();
    let record = ClickRecord { hwnd: WINDOW, message: WM_RBUTTONDOWN, wparam: 1, time_ms: 1_000, point: (3, 4) };
    context.time_ms = 1_100;
    context.modal = true;
    assert_eq!(prepare(click(WM_RBUTTONDOWN, 3, 4), Some(record), &context).message.message,
        WM_RBUTTONDOWN + (WM_LBUTTONDBLCLK - WM_LBUTTONDOWN));
    context.modal = false;
    context.hit_test = HTCAPTION;
    assert_eq!(prepare(click(WM_RBUTTONDOWN, 3, 4), Some(record), &context).message.message,
        WM_RBUTTONDOWN + (WM_LBUTTONDBLCLK - WM_LBUTTONDOWN) - (WM_MOUSEMOVE - WM_NCMOUSEMOVE));
}

#[test]
fn the_double_click_test_bounds_time_distance_window_message_and_button() {
    let context = MouseContext { class_dbl_clks: true, time_ms: 1_400, ..ctx() };
    let base = ClickRecord { hwnd: WINDOW, message: WM_LBUTTONDOWN, wparam: 1, time_ms: 1_000, point: (10, 10) };
    let now = |x, y| ClickRecord { time_ms: 1_400, point: (x, y), ..base };
    assert!(is_double_click(Some(base), now(10, 10), &context));
    // Half the 4-pixel rectangle: a 1-pixel move is inside, a 2-pixel move is
    // not, on either axis.
    assert!(is_double_click(Some(base), now(11, 11), &context));
    assert!(!is_double_click(Some(base), now(12, 10), &context));
    assert!(!is_double_click(Some(base), now(10, 8), &context));
    // The interval is exclusive at the double-click time.
    assert!(!is_double_click(Some(base), ClickRecord { time_ms: 1_500, ..base }, &context));
    assert!(is_double_click(Some(base), ClickRecord { time_ms: 1_499, ..base }, &context));
    // A different window, a different button, or a different button state is
    // a new first click.
    assert!(!is_double_click(Some(base), ClickRecord { hwnd: WINDOW + 1, ..now(10, 10) }, &context));
    assert!(!is_double_click(Some(base), ClickRecord { message: WM_RBUTTONDOWN, ..now(10, 10) }, &context));
    assert!(!is_double_click(Some(base), ClickRecord { wparam: 3, ..now(10, 10) }, &context));
    assert!(!is_double_click(None, now(10, 10), &context));
}

#[test]
fn a_peek_never_disturbs_the_remembered_click() {
    let context = MouseContext { remove: false, class_dbl_clks: true, ..ctx() };
    assert_eq!(prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context).click, ClickUpdate::Keep);
    let record = ClickRecord { hwnd: WINDOW, message: WM_LBUTTONDOWN, wparam: 1, time_ms: 1_000, point: (3, 4) };
    let prepared = prepare(click(WM_LBUTTONDOWN, 3, 4), Some(record), &MouseContext { time_ms: 1_100, ..context });
    assert_eq!(prepared.message.message, WM_LBUTTONDBLCLK);
    assert_eq!(prepared.click, ClickUpdate::Keep);
}

#[test]
fn a_pointer_move_runs_the_ladder_so_the_cursor_is_still_set() {
    assert_eq!(prepare(click(WM_MOUSEMOVE, 3, 4), None, &ctx()).outcome, MouseOutcome::Ladder);
    assert_eq!(prepare(click(WM_MOUSEMOVE, 3, 4), None, &ctx()).click, ClickUpdate::Keep);
}

#[test]
fn a_retrieval_naming_neither_end_of_the_range_admits_every_pointer_message() {
    // GetMessage(&msg, NULL, 0, 0) asks for every message. Reading the two
    // ends of that filter literally made every pointer message fall outside
    // the range, and the retrieval ate the whole click.
    let context = MouseContext { filter: range(0, 0), ..ctx() };
    for message in [WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_MOUSEWHEEL, WM_MOUSELAST] {
        let prepared = prepare(click(message, 3, 4), None, &context);
        assert_ne!(prepared.outcome, MouseOutcome::Filtered, "pointer message dropped by an unrestricted retrieval");
    }
    assert_eq!(prepare(click(WM_LBUTTONDOWN, 3, 4), None, &context).outcome, MouseOutcome::Ladder);
}
