// Stale-handle retry decision for path-based syscalls. Ungated so the rule is
// testable: the `*at` resolution layer that consumes it
// (`pathresolve/at.rs`) is kernel-gated, where a `#[cfg(test)] mod tests`
// compiles out silently.
//
// Contract (path-based syscall family): when a path walk reports a stale
// handle, the walk is retried ONCE with forced revalidation added to the
// lookup flags, and the second walk's result is final whatever it is. A walk
// that already carried forced revalidation is never retried — that is the
// bound which keeps a persistently stale backing store from spinning the
// syscall forever.

use syscall::errno::Errno;

/// Extra walks a stale-handle failure may buy, over and above the first one.
/// One, never more: the retry exists to give a filesystem a single chance to
/// re-resolve from its backing store, not to poll it.
pub const ESTALE_MAX_RETRIES: u32 = 1;

/// Outcome of the stale-handle check for one failed walk.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EstaleRetry {
    /// Report the error; it is final.
    Stop,
    /// Walk once more, with forced revalidation set in the lookup flags.
    RetryWithReval,
}

/// Should a failed path walk be re-attempted, and with what lookup flags?
///
/// `err` is the negated errno the walk produced; `reval` is whether that walk
/// already carried forced revalidation. Only a stale-handle error qualifies,
/// and only on a walk that trusted the cache — so the answer names both halves
/// of the decision: whether to retry at all, and that the retry walk gets
/// forced revalidation.
/// # C: O(1)
pub fn estale_retry_decision(err: i64, reval: bool) -> EstaleRetry {
    const ESTALE: i64 = -(Errno::Estale.as_i32() as i64);
    if err == ESTALE && !reval { EstaleRetry::RetryWithReval } else { EstaleRetry::Stop }
}

/// Run `walk` under the stale-handle retry contract.
///
/// `walk` receives the forced-revalidation flag to use for that attempt and
/// returns the walk's result. The first attempt uses `reval`; a stale-handle
/// failure buys at most [`ESTALE_MAX_RETRIES`] further attempts, each with the
/// flag set, and whatever the last attempt returns is what the caller sees.
/// The attempt counter is an independent hard bound on top of the flag test in
/// [`estale_retry_decision`], so neither alone can produce an unbounded loop.
/// # C: O(ESTALE_MAX_RETRIES) × cost of `walk`
pub fn with_estale_retry<T, F>(reval: bool, mut walk: F) -> Result<T, i64>
where F: FnMut(bool) -> Result<T, i64> {
    let mut reval = reval;
    let mut failures = 0u32;
    loop {
        let err = match walk(reval) { ok @ Ok(_) => return ok, Err(e) => e };
        failures += 1;
        if failures > ESTALE_MAX_RETRIES { return Err(err); }
        match estale_retry_decision(err, reval) {
            EstaleRetry::Stop => return Err(err),
            EstaleRetry::RetryWithReval => reval = true,
        }
    }
}

// Tests live in `tests/estale_retry_hosted.rs`: this module is also pulled in
// by `#[path]` from the hosted `*at` resolution tests, and an inline
// `mod tests` would be compiled once per those binaries.
