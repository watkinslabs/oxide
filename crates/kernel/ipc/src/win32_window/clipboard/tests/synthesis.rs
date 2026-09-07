//! Close-time format synthesis and the sequence number it advances.
use super::*;

fn window(raw: u32) -> Option<WindowId> { WindowId::from_raw(raw) }

#[test]
fn closing_a_text_only_transaction_offers_the_other_text_formats_and_the_locale() {
    let mut clipboard = ClipboardManager::new();
    clipboard.open(7, window(1)).unwrap();
    clipboard.empty(7).unwrap();
    clipboard.set_data(CF_TEXT, Some(b"a"), 0x409).unwrap();
    clipboard.close(7).unwrap();
    let ids = clipboard.format_ids();
    assert!(ids.contains(&CF_LOCALE) && ids.contains(&CF_OEMTEXT) && ids.contains(&CF_UNICODETEXT));
    clipboard.open(7, window(1)).unwrap();
    let synthesized = clipboard.data(7, CF_UNICODETEXT).unwrap();
    assert_eq!((synthesized.from, synthesized.data.is_none()), (CF_TEXT, true));
    assert_eq!(clipboard.data(7, CF_LOCALE).unwrap().data.as_deref(), Some(&0x409u32.to_le_bytes()[..]));
}

#[test]
fn a_bitmap_transaction_synthesizes_the_other_bitmap_formats_and_no_locale() {
    let mut clipboard = ClipboardManager::new();
    clipboard.open(7, window(1)).unwrap();
    clipboard.empty(7).unwrap();
    clipboard.set_data(CF_DIB, Some(b"px"), 0).unwrap();
    clipboard.close(7).unwrap();
    let ids = clipboard.format_ids();
    assert!(ids.contains(&CF_BITMAP) && ids.contains(&CF_DIBV5));
    assert!(!ids.contains(&CF_LOCALE));
}

#[test]
fn a_transaction_that_changed_nothing_synthesizes_nothing_and_names_no_viewer() {
    let mut clipboard = ClipboardManager::new();
    clipboard.set_viewer(window(4), None).unwrap();
    clipboard.open(7, window(1)).unwrap();
    let notify = clipboard.close(7).unwrap();
    assert_eq!(notify.viewer, None);
    assert_eq!(clipboard.count(), 0);
}

#[test]
fn a_transaction_that_changed_the_store_names_the_viewer_to_notify() {
    let mut clipboard = ClipboardManager::new();
    clipboard.set_viewer(window(4), None).unwrap();
    clipboard.open(7, window(1)).unwrap();
    clipboard.set_data(CF_TEXT, Some(b"a"), 0).unwrap();
    let before = clipboard.sequence();
    let notify = clipboard.close(7).unwrap();
    assert_eq!(notify.viewer, window(4));
    assert!(clipboard.sequence() > before);
}

#[test]
fn synthesis_never_displaces_a_format_the_owner_offered() {
    let mut clipboard = ClipboardManager::new();
    clipboard.open(7, window(1)).unwrap();
    clipboard.empty(7).unwrap();
    clipboard.set_data(CF_TEXT, Some(b"a"), 0).unwrap();
    clipboard.set_data(CF_UNICODETEXT, Some(b"b"), 0).unwrap();
    clipboard.close(7).unwrap();
    clipboard.open(7, window(1)).unwrap();
    assert_eq!(clipboard.data(7, CF_UNICODETEXT).unwrap().data.as_deref(), Some(&b"b"[..]));
}
