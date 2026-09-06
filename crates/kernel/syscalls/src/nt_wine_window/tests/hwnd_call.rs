use super::*;

const TOP: Snapshot = Snapshot { hwnd: 1, parent: 0, owner: 0, style: WS_VISIBLE, unicode: true, ancestors_visible: true, current_thread: true, text_length: 7, dpi: 96 };
const CHILD: Snapshot = Snapshot { hwnd: 2, parent: 1, owner: 0, style: WS_CHILD | WS_VISIBLE, unicode: false, ancestors_visible: true, current_thread: false, text_length: 0, dpi: 96 };

#[test]
fn a_null_handle_is_not_a_window_even_when_a_record_is_offered() {
    assert_eq!(answer(IS_WINDOW, 0, Some(TOP)), Answer::Value(0));
    assert_eq!(answer(IS_WINDOW, 9, None), Answer::Value(0));
    assert_eq!(answer(IS_WINDOW, 1, Some(TOP)), Answer::Value(1));
}

#[test]
fn predicates_read_the_style_and_ancestor_chain() {
    assert_eq!(answer(IS_WINDOW_VISIBLE, 1, Some(TOP)), Answer::Value(1));
    assert_eq!(answer(IS_WINDOW_VISIBLE, 2, Some(Snapshot { ancestors_visible: false, ..CHILD })), Answer::Value(0));
    assert_eq!(answer(IS_WINDOW_VISIBLE, 2, Some(Snapshot { style: WS_CHILD, ..CHILD })), Answer::Value(0));
    assert_eq!(answer(IS_WINDOW_ENABLED, 1, Some(TOP)), Answer::Value(1));
    assert_eq!(answer(IS_WINDOW_ENABLED, 1, Some(Snapshot { style: WS_DISABLED, ..TOP })), Answer::Value(0));
    assert_eq!(answer(IS_WINDOW_UNICODE, 2, Some(CHILD)), Answer::Value(0));
}

#[test]
fn parent_follows_popup_owner_then_child_parent() {
    assert_eq!(answer(GET_PARENT, 2, Some(CHILD)), Answer::Value(1));
    assert_eq!(answer(GET_PARENT, 3, Some(Snapshot { hwnd: 3, owner: 1, style: WS_POPUP, ..TOP })), Answer::Value(1));
    assert_eq!(answer(GET_PARENT, 1, Some(TOP)), Answer::Value(0));
}

#[test]
fn ownership_queries_return_the_handle_or_zero() {
    assert_eq!(answer(IS_CURRENT_THREAD_WINDOW, 1, Some(TOP)), Answer::Value(1));
    assert_eq!(answer(IS_CURRENT_THREAD_WINDOW, 2, Some(CHILD)), Answer::Value(0));
    assert_eq!(answer(IS_CURRENT_PROCESS_WINDOW, 2, Some(CHILD)), Answer::Value(2));
    assert_eq!(answer(GET_FULL_WINDOW_HANDLE, 2, Some(CHILD)), Answer::Value(2));
    assert_eq!(answer(GET_WINDOW_TEXT_LENGTH, 1, Some(TOP)), Answer::Value(7));
    assert_eq!(answer(GET_DPI_FOR_WINDOW, 1, Some(TOP)), Answer::Value(96));
}

#[test]
fn an_unknown_code_is_reported_not_guessed() {
    assert_eq!(answer(99, 1, Some(TOP)), Answer::Unsupported(99));
    assert_eq!(answer(99, 0, None), Answer::Unsupported(99));
}
