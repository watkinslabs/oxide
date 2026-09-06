use super::*;

#[test]
fn stale_slow_reader_cannot_overwrite_fast_reader_count() {
    let sem = VfsRwsem::<sync::Inode>::new();
    let observed = sem.state.load(Ordering::Acquire);
    sem.state.fetch_add(1, Ordering::Acquire);
    assert!(!sem.claim_reader(observed));
    assert_eq!(sem.debug_state(), (1, false));
    assert!(sem.claim_reader(1));
    assert_eq!(sem.debug_state(), (2, false));
}

#[test]
fn writer_claim_cannot_overwrite_admitted_reader() {
    let sem = VfsRwsem::<sync::Inode>::new();
    sem.state.fetch_add(1, Ordering::Acquire);
    assert!(!sem.claim_writer());
    assert_eq!(sem.debug_state(), (1, false));
    sem.state.fetch_sub(1, Ordering::Release);
    assert!(sem.claim_writer());
    assert_eq!(sem.debug_state(), (0, true));
}
