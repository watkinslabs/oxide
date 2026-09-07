use super::*;

#[test]
fn arguments_the_caller_holds_are_never_read_from_the_stack() {
    let mut reads = alloc::vec::Vec::new();
    let full = collect(&[1, 2, 3], 3, |index| { reads.push(index); Some(0) }).unwrap();
    assert!(reads.is_empty());
    assert_eq!(&full[..3], &[1, 2, 3]);
}

#[test]
fn the_tail_continues_at_the_logical_index_the_signature_gives_it() {
    let mut reads = alloc::vec::Vec::new();
    let full = collect(&[1, 2, 3, 4, 5, 6], 10, |index| { reads.push(index); Some(0x7000 + index as u64) }).unwrap();
    assert_eq!(reads, [6, 7, 8, 9]);
    assert_eq!(&full[..10], &[1, 2, 3, 4, 5, 6, 0x7006, 0x7007, 0x7008, 0x7009]);
    // Nothing past the signature is read or written.
    assert!(full[10..].iter().all(|value| *value == 0));
}

#[test]
fn a_stack_word_that_cannot_be_read_fails_the_whole_collection() {
    assert_eq!(collect(&[1, 2, 3, 4, 5, 6], 8, |index| (index != 7).then_some(0)), None);
}

#[test]
fn a_signature_longer_than_the_entry_admits_is_clamped_rather_than_overrunning() {
    let full = collect(&[], MAX_RAW_ARGUMENTS + 5, |index| Some(index as u64)).unwrap();
    assert_eq!(full[MAX_RAW_ARGUMENTS - 1], (MAX_RAW_ARGUMENTS - 1) as u64);
}
