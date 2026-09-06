use super::*;

#[test]
fn the_unaware_context_matches_the_packed_layout() {
    assert_eq!(UNAWARE, 0x6010);
    assert_eq!(make(1, 1, 96, 0), 0x6011);
    assert_eq!(make(2, 2, 0, 0), 0x0022);
}

#[test]
fn an_unset_process_is_unaware_and_other_processes_are_not_reported() {
    assert_eq!(get(0, 0), UNAWARE);
    assert_eq!(get(0, CURRENT_PROCESS), UNAWARE);
    assert_eq!(get(0x6011, CURRENT_PROCESS), 0x6011);
    assert_eq!(get(0x6011, 0), 0x6011);
    assert_eq!(get(0x6011, 0x1234), UNAWARE);
}

#[test]
fn validity_follows_awareness() {
    assert!(is_valid(UNAWARE, 96));
    assert!(is_valid(UNAWARE | 0x8000_0000, 96));
    assert!(!is_valid(UNAWARE | 0x0002_0000, 96));
    assert!(!is_valid(make(0, 2, 96, 0), 96));
    assert!(!is_valid(make(0, 1, 120, 0), 96));
    assert!(is_valid(make(1, 1, 120, 0), 120));
    assert!(!is_valid(make(1, 1, 96, 0), 120));
    assert!(is_valid(make(1, 1, 96, 0), 0));
    assert!(!is_valid(make(1, 1, 120, 0x4000_0000), 120));
    assert!(is_valid(make(2, 1, 0, 0), 96));
    assert!(is_valid(make(2, 2, 0, 0), 96));
    assert!(!is_valid(make(2, 3, 0, 0), 96));
    assert!(!is_valid(make(2, 1, 96, 0), 96));
    assert!(!is_valid(make(3, 1, 0, 0), 96));
    assert!(!is_valid(0xc000_001c, 96));
}

#[test]
fn the_context_is_set_once() {
    let mut stored = 0;
    assert_eq!(set(&mut stored, 0xc000_001c, 96), Err(ERROR_INVALID_PARAMETER));
    assert_eq!(stored, 0);
    assert_eq!(set(&mut stored, make(1, 1, 96, 0), 96), Ok(()));
    assert_eq!(stored, 0x6011);
    assert_eq!(set(&mut stored, UNAWARE, 96), Err(ERROR_ACCESS_DENIED));
    assert_eq!(stored, 0x6011);
    assert_eq!(get(stored, CURRENT_PROCESS), 0x6011);
}
