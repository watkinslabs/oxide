use super::*;
use ipc::win32_window::WindowManager;

#[test]
fn long_raw_pinned_ordinals_and_register_widths() {
    assert_eq!((SET_LONG, SET_PTR, SET_WORD), (0x15a3, 0x15a4, 0x15ad));
    let args = [1, 0xdead_beef_ffff_ffeb, 0x1234_5678_8000_0001, 0xfeed_0000_0000];
    let long = decode(SET_LONG, args).unwrap();
    assert_eq!((long.index, long.width, long.value, long.ansi), (-21, 4, 0xffff_ffff_8000_0001, false));
    assert_eq!(decode(SET_PTR, args).unwrap().value, args[2]);
    let word = decode(SET_WORD, args).unwrap();
    assert_eq!((word.width, word.value, word.ansi), (2, 1, true));
    assert!(decode(0x15a5, args).is_none());
}

#[test]
fn long_raw_edit_offset_zero_calls_actual_class_storage() {
    let mut owner = WindowManager::new();
    let atom = owner.register_class_with_extra(&[69, 68, 73, 84], 0x1000, 8).unwrap();
    let hwnd = owner.create_class_atom(7, None, atom).unwrap();
    let mut error = 123;
    let request = decode(SET_PTR, [hwnd.raw() as u64, 0, 0x7f65_1234_5678, 0]).unwrap();
    assert_eq!(set_with(request, |r| owner.set_window_long(hwnd, r.index, r.width, r.value), |e| error = e), 0);
    assert_eq!(error, 123);
    assert_eq!(finish(owner.get_window_long_ptr(hwnd, 0), 8, |e| error = e), 0x7f65_1234_5678);
    let bad = decode(SET_PTR, [hwnd.raw() as u64, 1, 0, 0]).unwrap();
    assert_eq!(set_with(bad, |r| owner.set_window_long(hwnd, r.index, r.width, r.value), |e| error = e), 0);
    assert_eq!(error, 1413);
    assert_eq!(owner.get_window_long_ptr(hwnd, 0), Ok(0x7f65_1234_5678));
}

#[test]
fn long_raw_word_index_precedes_broadcast_and_owner_lookup() {
    let mut error = 0;
    let word = decode(SET_WORD, [u64::MAX, (-4i32) as u64, 0, 0]).unwrap();
    assert_eq!(set_with(word, |_| panic!("must not access owner"), |e| error = e), 0);
    assert_eq!(error, 1413);
    for hwnd in [0xffff, u64::MAX] {
        let request = decode(SET_PTR, [hwnd, 0, 0, 0]).unwrap();
        assert_eq!(set_with(request, |_| panic!("must not access owner"), |e| error = e), 0);
        assert_eq!(error, 87);
    }
}

#[test]
fn long_raw_failures_and_successful_zero_do_not_share_error_channel() {
    let mut error = 77;
    for (failure, code) in [(LongPtrError::InvalidWindow, 1400), (LongPtrError::InvalidIndex, 1413),
        (LongPtrError::InvalidSize, 87), (LongPtrError::NoMemory, 8), (LongPtrError::OwnerTransaction, 120)] {
        assert_eq!(finish(Err(failure), 8, |e| error = e), 0);
        assert_eq!(error, code);
    }
    assert_eq!(finish(Ok(0), 8, |e| error = e), 0);
    assert_eq!(error, 120);
    assert_eq!(finish(Ok(u64::MAX), 4, |_| panic!("success changed LastError")), u32::MAX as u64);
    assert_eq!(finish(Ok(u64::MAX), 2, |_| panic!("success changed LastError")), u16::MAX as u64);
}
