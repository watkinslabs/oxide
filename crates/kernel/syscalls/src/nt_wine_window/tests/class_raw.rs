use super::*;

const HWND: u64 = 0x20;
const GCLP_HCURSOR: i32 = -12;

// The read methods are named by the one NtUserCallHwndParam decoder, whose
// own tests pin each width and encoding; this file owns the write ordinals.

#[test]
fn each_write_ordinal_normalises_its_value_to_the_written_width() {
    assert_eq!(decode_set(SET_CLASS_WORD, [HWND, 0, 0x1_2345, 0]).map(|(_, value)| value), Some(0x2345));
    assert_eq!(decode_set(SET_CLASS_LONG, [HWND, 0, 0xffff_ffff, 0]).map(|(_, value)| value), Some(u64::MAX));
    assert_eq!(decode_set(SET_CLASS_LONG_PTR, [HWND, 0, 0xffff_ffff, 0]).map(|(_, value)| value), Some(0xffff_ffff));
    assert_eq!(decode_set(SET_CLASS_LONG, [HWND, 0, 0, 1]).map(|(request, _)| request.ansi), Some(true));
    assert_eq!(decode_set(SET_CLASS_WORD, [HWND, 0, 0, 0]).map(|(request, _)| request.ansi), Some(true));
    assert_eq!(decode_set(0x15a3, [HWND, 0, 0, 0]), None);
}

#[test]
fn a_negative_offset_survives_the_thirty_two_bit_argument() {
    let (request, _) = decode_set(SET_CLASS_LONG_PTR, [HWND, GCLP_HCURSOR as u32 as u64, 7, 0]).unwrap();
    assert_eq!(request.offset, GCLP_HCURSOR);
}

#[test]
fn a_rejected_access_answers_zero_and_names_the_win32_error() {
    let mut errors = alloc::vec::Vec::new();
    let request = ClassLong { hwnd: HWND, offset: 4, width: 4, ansi: false };
    assert_eq!(access_with(request, |_| Err(LongPtrError::InvalidIndex), |error| errors.push(error)), 0);
    assert_eq!(errors, alloc::vec![1413]);
    let mut errors = alloc::vec::Vec::new();
    assert_eq!(access_with(request, |_| Err(LongPtrError::InvalidWindow), |error| errors.push(error)), 0);
    assert_eq!(errors, alloc::vec![1400]);
}

#[test]
fn a_successful_access_truncates_to_the_width_and_keeps_the_last_error() {
    let mut errors = alloc::vec::Vec::new();
    let request = ClassLong { hwnd: HWND, offset: GCLP_HCURSOR, width: 4, ansi: false };
    assert_eq!(access_with(request, |_| Ok(0x1_2345_6789), |error| errors.push(error)), 0x2345_6789);
    assert!(errors.is_empty());
}
