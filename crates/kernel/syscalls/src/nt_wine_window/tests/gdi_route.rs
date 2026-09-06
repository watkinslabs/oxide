use super::*;
use alloc::vec::Vec;

#[test]
fn raw_text_reads_exact_tail_and_reaches_typed_operation() {
    let mut reads = Vec::new();
    let operation = collect(gdi_raw::EXT_TEXT_OUT_W, [1, 2, 3, 4, 5, 6], |index| {
        reads.push(index); Some(index as u64 + 10)
    });
    assert_eq!(reads, [6, 7, 8]);
    assert_eq!(operation, Some(Ok(gdi_raw::Operation::ExtTextOutW {
        dc: 1, x: 2, y: 3, flags: 4, rect: 5, text: 6, count: 16, dx: 17, code_page: 18,
    })));
    let operation = collect(gdi_raw::GET_TEXT_EXTENT_EX_W, [0; 6], |index| (index < 8).then_some(index as u64));
    assert!(matches!(operation, Some(Ok(gdi_raw::Operation::GetTextExtentExW { extent: 6, flags: 7, .. }))));
}

#[test]
fn raw_short_and_unclaimed_calls_do_not_touch_user_stack() {
    assert_eq!(collect(gdi_raw::DELETE_OBJECT_APP, [12, 0, 0, 0, 0, 0], |_| panic!("unowned stack read")),
        Some(Ok(gdi_raw::Operation::DeleteObject { handle: 12 })));
    assert_eq!(collect(0xffff, [0; 6], |_| panic!("unclaimed stack read")), None);
}

#[test]
fn raw_tail_fault_cannot_reach_execution() {
    for missing in 6..9 {
        assert_eq!(collect(gdi_raw::EXT_TEXT_OUT_W, [0; 6], |index| (index != missing).then_some(1)), Some(Err(())));
    }
}
