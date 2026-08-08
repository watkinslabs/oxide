//! Stale-handle retry contract for the path-based syscall family (the
//! `faccessat2` row's remaining half, applied tree-wide at the `*at`
//! resolution layer).
//!
//! Verified behaviour pinned here, so the contract is re-checkable without
//! reading any other implementation:
//!
//!   1. A path walk that fails with a stale-handle error, on a walk that
//!      trusted the dentry cache, is retried.
//!   2. The retry walk carries forced revalidation in its lookup flags.
//!   3. The retry happens AT MOST ONCE — a walk that already forced
//!      revalidation is never retried, however it fails.
//!   4. The second walk's result is final whatever it is: success, the same
//!      stale-handle error, or a different error entirely.
//!   5. Any non-stale error is reported as-is, with no second walk.

use syscall::errno::Errno;
use syscalls::estale_retry::{ESTALE_MAX_RETRIES, EstaleRetry, estale_retry_decision, with_estale_retry};

const ESTALE: i64 = -(Errno::Estale.as_i32() as i64);
const ENOENT: i64 = -(Errno::Enoent.as_i32() as i64);

#[test]
fn a_stale_handle_on_a_cache_trusting_walk_buys_one_revalidating_retry() {
    assert_eq!(estale_retry_decision(ESTALE, false), EstaleRetry::RetryWithReval);
}

#[test]
fn a_stale_handle_on_the_revalidating_walk_is_final() {
    // The bound. Without it a persistently stale backing store spins the
    // syscall forever.
    assert_eq!(estale_retry_decision(ESTALE, true), EstaleRetry::Stop);
}

#[test]
fn any_other_error_is_reported_as_is() {
    assert_eq!(estale_retry_decision(ENOENT, false), EstaleRetry::Stop);
    assert_eq!(estale_retry_decision(ENOENT, true), EstaleRetry::Stop);
}

#[test]
fn the_retry_budget_is_exactly_one_extra_walk() {
    assert_eq!(ESTALE_MAX_RETRIES, 1);
}

#[test]
fn a_walk_that_succeeds_runs_once_and_never_forces_revalidation() {
    let mut seen: Vec<bool> = Vec::new();
    let r: Result<u32, i64> = with_estale_retry(false, |reval| { seen.push(reval); Ok(7) });
    assert_eq!(r, Ok(7));
    assert_eq!(seen, [false]);
}

#[test]
fn a_stale_first_walk_is_retried_once_with_revalidation_and_that_result_stands() {
    let mut seen: Vec<bool> = Vec::new();
    let r: Result<u32, i64> = with_estale_retry(false, |reval| {
        seen.push(reval);
        if reval { Ok(9) } else { Err(ESTALE) }
    });
    assert_eq!(r, Ok(9));
    assert_eq!(seen, [false, true]);
}

#[test]
fn a_persistently_stale_path_stops_after_exactly_two_walks() {
    let mut walks = 0u32;
    let r: Result<u32, i64> = with_estale_retry(false, |_| { walks += 1; Err(ESTALE) });
    assert_eq!(r, Err(ESTALE));
    assert_eq!(walks, 2);
}

#[test]
fn the_second_walks_error_is_final_even_when_it_differs() {
    let mut walks = 0u32;
    let r: Result<u32, i64> = with_estale_retry(false, |_| {
        walks += 1;
        if walks == 1 { Err(ESTALE) } else { Err(ENOENT) }
    });
    assert_eq!(r, Err(ENOENT));
    assert_eq!(walks, 2);
}

#[test]
fn a_non_stale_failure_is_never_retried() {
    let mut walks = 0u32;
    let r: Result<u32, i64> = with_estale_retry(false, |_| { walks += 1; Err(ENOENT) });
    assert_eq!(r, Err(ENOENT));
    assert_eq!(walks, 1);
}

#[test]
fn a_walk_that_already_forced_revalidation_gets_no_retry() {
    let mut walks = 0u32;
    let r: Result<u32, i64> = with_estale_retry(true, |reval| {
        assert!(reval);
        walks += 1;
        Err(ESTALE)
    });
    assert_eq!(r, Err(ESTALE));
    assert_eq!(walks, 1);
}
