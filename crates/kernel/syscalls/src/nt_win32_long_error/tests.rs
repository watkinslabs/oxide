use super::*;

#[test]
fn every_owner_error_names_one_win32_error() {
    assert_eq!(win32_error(LongPtrError::InvalidWindow), 1400);
    assert_eq!(win32_error(LongPtrError::InvalidIndex), 1413);
    assert_eq!(win32_error(LongPtrError::InvalidSize), 87);
    assert_eq!(win32_error(LongPtrError::NoMemory), 8);
    assert_eq!(win32_error(LongPtrError::OwnerTransaction), 120);
}

#[test]
fn a_successful_zero_is_not_a_failure() {
    let mut errors = alloc::vec::Vec::new();
    assert_eq!(finish(Ok(0), 8, |error| errors.push(error)), 0);
    assert!(errors.is_empty());
    assert_eq!(finish(Ok(0x1_2345_6789_abcd), 4, |_| ()), 0x6789_abcd);
    assert_eq!(finish(Ok(0x1_2345), 2, |_| ()), 0x2345);
}
