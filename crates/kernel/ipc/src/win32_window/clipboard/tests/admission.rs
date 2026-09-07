//! Open/close/read/write admission ladder and the viewer/listener contracts.
use super::*;

fn window(raw: u32) -> Option<WindowId> { WindowId::from_raw(raw) }

#[test]
fn a_second_window_cannot_take_the_clipboard_while_another_holds_it_open() {
    let mut clipboard = ClipboardManager::new();
    assert_eq!(clipboard.open(7, window(1)), Ok(None));
    assert_eq!(clipboard.open(8, window(2)), Err(ClipboardError::InvalidLockSequence));
    // The same window reopening from another thread is admitted.
    assert_eq!(clipboard.open(8, window(1)), Ok(None));
    assert!(clipboard.is_open());
}

#[test]
fn close_is_refused_from_a_thread_that_does_not_hold_the_transaction() {
    let mut clipboard = ClipboardManager::new();
    clipboard.open(7, window(1)).unwrap();
    assert_eq!(clipboard.close(8), Err(ClipboardError::NotOpen));
    assert!(clipboard.close(7).is_ok());
    assert!(!clipboard.is_open());
}

#[test]
fn writing_needs_an_open_transaction_and_a_non_zero_format() {
    let mut clipboard = ClipboardManager::new();
    assert_eq!(clipboard.set_data(CF_TEXT, Some(b"hi"), 0), Err(ClipboardError::NotOpen));
    clipboard.open(7, window(1)).unwrap();
    assert_eq!(clipboard.set_data(0, Some(b"hi"), 0), Err(ClipboardError::NotOpen));
    assert_eq!(clipboard.set_data(CF_TEXT, Some(b"hi"), 0x409), Ok(0));
    assert_eq!(clipboard.lcid(), 0x409);
    assert_eq!(clipboard.count(), 1);
}

#[test]
fn reading_is_restricted_to_the_opening_thread_and_reports_a_missing_format() {
    let mut clipboard = ClipboardManager::new();
    clipboard.open(7, window(1)).unwrap();
    clipboard.set_data(CF_TEXT, Some(b"hi"), 0).unwrap();
    assert_eq!(clipboard.data(8, CF_TEXT).err(), Some(ClipboardError::NotOpen));
    assert_eq!(clipboard.data(7, CF_UNICODETEXT).err(), Some(ClipboardError::NotFound));
    assert_eq!(clipboard.data(7, CF_TEXT).unwrap().data.as_deref(), Some(&b"hi"[..]));
}

#[test]
fn empty_takes_ownership_for_the_opening_window_and_advances_the_sequence() {
    let mut clipboard = ClipboardManager::new();
    clipboard.open(7, window(4)).unwrap();
    clipboard.set_data(CF_TEXT, Some(b"a"), 0).unwrap();
    let before = clipboard.sequence();
    assert_eq!(clipboard.empty(8), Err(ClipboardError::NotOpen));
    assert!(clipboard.empty(7).is_ok());
    assert_eq!(clipboard.owner(), window(4));
    assert_eq!(clipboard.count(), 0);
    assert_eq!(clipboard.sequence(), before + 1);
}

#[test]
fn enumeration_walks_the_offer_order_from_zero_and_ends_at_zero() {
    let mut clipboard = ClipboardManager::new();
    clipboard.open(7, window(1)).unwrap();
    clipboard.set_data(CF_TEXT, Some(b"a"), 0).unwrap();
    clipboard.set_data(CF_UNICODETEXT, Some(b"b"), 0).unwrap();
    assert_eq!(clipboard.enum_formats(7, 0), Ok(CF_TEXT));
    assert_eq!(clipboard.enum_formats(7, CF_TEXT), Ok(CF_UNICODETEXT));
    assert_eq!(clipboard.enum_formats(7, CF_UNICODETEXT), Ok(0));
    assert_eq!(clipboard.enum_formats(8, 0), Err(ClipboardError::NotOpen));
}

#[test]
fn the_priority_query_separates_an_empty_store_from_an_unmatched_list() {
    let mut clipboard = ClipboardManager::new();
    assert_eq!(clipboard.priority_format(&[CF_TEXT]), 0);
    clipboard.open(7, window(1)).unwrap();
    clipboard.set_data(CF_UNICODETEXT, Some(b"a"), 0).unwrap();
    assert_eq!(clipboard.priority_format(&[CF_TEXT, CF_UNICODETEXT]), CF_UNICODETEXT as i32);
    assert_eq!(clipboard.priority_format(&[CF_BITMAP]), -1);
    assert!(!clipboard.is_available(0));
}

#[test]
fn a_viewer_install_that_names_a_stale_predecessor_defers_to_the_message_chain() {
    let mut clipboard = ClipboardManager::new();
    assert_eq!(clipboard.set_viewer(window(1), None), Ok((None, None)));
    assert_eq!(clipboard.set_viewer(window(2), window(9)), Err(ClipboardError::Pending));
    assert_eq!(clipboard.viewer(), window(1));
    assert_eq!(clipboard.set_viewer(window(2), window(1)), Ok((window(1), None)));
}

#[test]
fn a_listener_registers_once_and_unregisters_once() {
    let mut clipboard = ClipboardManager::new();
    let hwnd = window(5).unwrap();
    assert_eq!(clipboard.add_listener(hwnd), Ok(()));
    assert_eq!(clipboard.add_listener(hwnd), Err(ClipboardError::InvalidParameter));
    assert_eq!(clipboard.listeners(), &[hwnd]);
    assert_eq!(clipboard.remove_listener(hwnd), Ok(()));
    assert_eq!(clipboard.remove_listener(hwnd), Err(ClipboardError::InvalidParameter));
}

#[test]
fn destroying_the_open_window_closes_the_transaction_and_drops_its_references() {
    let mut clipboard = ClipboardManager::new();
    let hwnd = window(3).unwrap();
    clipboard.add_listener(hwnd).unwrap();
    clipboard.set_viewer(Some(hwnd), None).unwrap();
    clipboard.open(7, Some(hwnd)).unwrap();
    clipboard.empty(7).unwrap();
    clipboard.set_data(CF_TEXT, Some(b"a"), 0).unwrap();
    let notify = clipboard.cleanup_window(hwnd);
    assert_eq!(notify.viewer, None);
    assert_eq!(clipboard.listeners(), &[]);
    assert_eq!(clipboard.owner(), None);
    assert!(!clipboard.is_open());
}

#[test]
fn an_exiting_thread_releases_only_its_own_transaction() {
    let mut clipboard = ClipboardManager::new();
    clipboard.open(7, window(1)).unwrap();
    assert_eq!(clipboard.cleanup_thread(9), ClipboardNotify::default());
    assert!(clipboard.is_open());
    clipboard.cleanup_thread(7);
    assert!(!clipboard.is_open());
}

#[test]
fn releasing_the_owner_drops_the_formats_it_can_no_longer_render() {
    let mut clipboard = ClipboardManager::new();
    let hwnd = window(2).unwrap();
    clipboard.open(7, Some(hwnd)).unwrap();
    clipboard.empty(7).unwrap();
    clipboard.set_data(CF_TEXT, Some(b"a"), 0).unwrap();
    clipboard.set_data(CF_UNICODETEXT, None, 0).unwrap();
    assert_eq!(clipboard.release_owner(window(9).unwrap()).err(), Some(ClipboardError::InvalidOwner));
    let notify = clipboard.release_owner(hwnd).unwrap();
    assert_eq!(notify.owner, None);
    assert_eq!(clipboard.format_ids(), alloc::vec![CF_TEXT]);
}
