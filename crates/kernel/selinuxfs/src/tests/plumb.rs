use super::*;
use alloc::vec::Vec;

#[test]
fn caller_bytes_are_copied_into_kernel_memory() {
    // The copy is what makes "a handler must not touch caller memory under a
    // lock" structural rather than a rule every handler has to remember. If
    // the returned buffer is the caller's own, a demand fault on it can land
    // inside a handler that already holds the security server's lock, and the
    // scheduler reports a violation on every write.
    let caller = alloc::vec![1u8, 2, 3, 4, 5];
    let copied = dup_caller_bytes(&caller).expect("copy");
    assert_eq!(copied, caller, "the copy must carry the same bytes");
    assert_ne!(copied.as_ptr(), caller.as_ptr(),
               "the handler must not be handed the caller's own memory");
}

#[test]
fn an_empty_write_copies_to_an_empty_buffer() {
    assert!(dup_caller_bytes(&[]).expect("copy").is_empty());
}

#[test]
fn a_copy_preserves_length_exactly() {
    for len in [0usize, 1, 7, 64, 4096, 4097] {
        let caller: Vec<u8> = (0..len).map(|i| i as u8).collect();
        assert_eq!(dup_caller_bytes(&caller).expect("copy").len(), len);
    }
}

#[test]
fn slice_at_takes_only_what_the_reader_asked_for() {
    let body = alloc::vec![10u8, 11, 12, 13, 14];
    assert_eq!(slice_at(&body, 0, 3), alloc::vec![10, 11, 12]);
    assert_eq!(slice_at(&body, 2, 10), alloc::vec![12, 13, 14]);
    assert_eq!(slice_at(&body, 5, 4), Vec::new(), "an offset at the end reads nothing");
    assert_eq!(slice_at(&body, 99, 4), Vec::new(), "an offset past the end reads nothing");
    assert_eq!(slice_at(&body, 1, 0), Vec::new());
}

#[test]
fn a_staged_read_reproduces_a_direct_one() {
    // The staged form exists so a reader can drop its lock before touching
    // caller memory; it must not change what the reader returns.
    let body: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    for (off, len) in [(0u64, 16usize), (7, 5), (0, 400), (199, 4), (200, 4)] {
        let mut direct = alloc::vec![0u8; len];
        let n_direct = copy_out(&body, off, &mut direct);
        let staged = slice_at(&body, off, len);
        let mut via = alloc::vec![0u8; len];
        let n_via = copy_out(&staged, 0, &mut via);
        assert_eq!(n_direct, n_via, "off={off} len={len}");
        assert_eq!(direct[..n_direct], via[..n_via], "off={off} len={len}");
    }
}
