use super::*;
use core::cell::Cell;
use ipc::win32_gdi::{FontRecord, GdiManager, DEFAULT_DC_FONT_HANDLE};

#[test]
fn canonical_font_query_counts_null_negative_partial_and_oversized() {
    let mut owner = GdiManager::new();
    let mut bytes = [0u8; 92];
    for (index, byte) in bytes.iter_mut().enumerate() { *byte = index as u8; }
    let handle = owner.create_font_record(FontRecord::from_bytes(bytes).unwrap()).unwrap();
    for (count, output, expected) in [(0, 0, 92), (-1, 0, 92), (1, 0, 92), (i32::MIN, 0, 92),
        (0, 0x10000, 0), (-1, 0x10000, 92), (i32::MIN, 0x10000, 92),
        (1, 0x10000, 1), (91, 0x10000, 91), (92, 0x10000, 92), (93, 0x10000, 92), (i32::MAX, 0x10000, 92)] {
        let written = Cell::new(false); let errored = Cell::new(false);
        let query = owner.query_font(handle, count, output != 0);
        assert_eq!(complete_query(query, output, |address, prefix| {
            assert_eq!(address, output); assert_eq!(prefix, &bytes[..expected]); written.set(true); true
        }, || errored.set(true)), expected as u64);
        assert_eq!(written.get(), output != 0 && expected != 0);
        assert!(!errored.get());
    }
}

#[test]
fn canonical_bad_handle_precedes_bad_pointer_and_never_changes_last_error() {
    let mut owner = GdiManager::new();
    let deleted = owner.create_font_record(FontRecord::from_bytes([0; 92]).unwrap()).unwrap();
    owner.delete_object(deleted).unwrap();
    let dc = owner.create_dc(1, 1).unwrap();
    for handle in [0, deleted, dc, DEFAULT_DC_FONT_HANDLE ^ 0x10000] {
        for output in [0, 1, 0xffff, 0x10000] {
            let touched = Cell::new(false);
            assert_eq!(complete_query(owner.query_font(handle, -1, output != 0), output,
                |_, _| { touched.set(true); true }, || touched.set(true)), 0);
            assert!(!touched.get());
        }
    }
    let error = Cell::new(false);
    assert_eq!(complete_query(owner.query_font(DEFAULT_DC_FONT_HANDLE, 0, true), 1,
        |_, _| false, || error.set(true)), 0);
    assert!(error.get());
}

#[test]
fn canonical_snapshot_transfer_reports_copy_failure_without_mutating_font() {
    let owner = GdiManager::new();
    let before = owner.font_record(DEFAULT_DC_FONT_HANDLE).unwrap();
    let writes = Cell::new(0);
    let result = complete_query(owner.query_font(DEFAULT_DC_FONT_HANDLE, -1, true), 0x10000,
        |_, bytes| { assert_eq!(bytes, before.bytes()); writes.set(writes.get() + 1); false }, || {});
    assert_eq!(result, 0); assert_eq!(writes.get(), 1);
    assert_eq!(owner.font_record(DEFAULT_DC_FONT_HANDLE).unwrap(), before);
}

#[test]
fn null_output_queries_size_without_copy_or_error() {
    let touched = Cell::new(false);
    assert_eq!(copy_query(&[0; 92], 0, |_, _| { touched.set(true); false }, || touched.set(true)), 92);
    assert!(!touched.get());
}

#[test]
fn low_nonnull_pointer_sets_error_before_even_empty_copy() {
    let wrote = Cell::new(false); let error = Cell::new(false);
    for bytes in [&[][..], &[7][..]] {
        error.set(false);
        assert_eq!(copy_query(bytes, 0xffff, |_, _| { wrote.set(true); true }, || error.set(true)), 0);
        assert!(error.get()); assert!(!wrote.get());
    }
}

#[test]
fn copy_uses_exact_prefix_and_propagates_usercopy_failure() {
    let copied = Cell::new(false);
    assert_eq!(copy_query(&[1, 2, 3], 0x10000, |address, bytes| {
        assert_eq!(address, 0x10000); assert_eq!(bytes, &[1, 2, 3]); copied.set(true); true
    }, || {}), 3);
    assert!(copied.get());
    assert_eq!(copy_query(&[1], 0x10000, |_, _| false, || {}), 0);
    copied.set(false);
    assert_eq!(copy_query(&[], 0x10000, |_, _| { copied.set(true); false }, || {}), 0);
    assert!(!copied.get());
}
