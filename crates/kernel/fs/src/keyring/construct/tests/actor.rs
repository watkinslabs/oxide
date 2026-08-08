// The suite's stand-in for `/sbin/request-key`.
//
// ONE actor is installed for the whole suite and selects its behaviour from the
// key's DESCRIPTION. A per-test actor would race: the actor is a single global
// and `cargo test` runs these in parallel.
//
// It is not a mock of the construction path — it drives the same
// `assume_authority_core` / `instantiate_core` / `reject_core` a real helper
// binary reaches through `keyctl(2)`, under a synthetic helper task whose
// session keyring is the one the construction path actually built for it.

use super::*;

/// The behaviour a test selects through the key description it asks for.
pub(super) fn behaviour(desc: &str) -> &'static str {
    for b in ["unrunnable", "silent", "negate", "reject", "dest", "deep", "chain", "execonly", "borrow",
        "sessiondest", "instantiate"]
    {
        if desc.starts_with(b) { return b; }
    }
    "instantiate"
}

/// A stand-in for `/sbin/request-key`, driven through the real keyctl cores.
pub(super) fn test_helper(a: &HelperArgs) -> i64 {
    let desc = STORE.lock().keys.get(&a.key).map(|k| k.description.clone()).unwrap_or_default();
    if desc == CACHED_DESC { CACHED_UPCALLS.fetch_add(1, Ordering::Relaxed); }
    match behaviour(&desc) {
        // The helper could not be run at all — what a missing binary or a
        // closed usermode-helper gate looks like.
        "unrunnable" => return -(Errno::Enoent.as_i32() as i64),
        // The helper ran, exited 0, and never answered the key. Its exit status
        // must NOT be mistaken for success.
        "silent" => return 0,
        _ => {}
    }
    let tid = HELPER_TID.fetch_add(1, Ordering::Relaxed);
    STORE.lock().session.insert(tid, a.helper_keyring);
    let h = ctx(tid, 0);
    // Exactly what a helper does first: pick up the token it was handed.
    let got = assume_authority_core(&h, a.key);
    assert_eq!(got, a.authkey as i64, "the helper finds its own token by searching its keyrings");
    let rc = match behaviour(&desc) {
        "negate" => reject_core(&h, a.key, 60, Errno::Enokey.as_i32() as u32, 0),
        "reject" => reject_core(&h, a.key, 60, Errno::Ekeyrejected.as_i32() as u32, 0),
        // Instantiate into the REQUESTOR's keyring rather than naming one.
        "dest" => instantiate_core(&h, a.key, b"from-helper".to_vec(), KEY_SPEC_REQUESTOR_KEYRING),
        // The shape a real `/sbin/request-key` has: assume authority, EXEC the
        // configured handler, and let a FORKED child answer the key. See
        // `chain`.
        "chain" => chain::answer_after_exec_and_fork(a, tid),
        // The same, one level deeper and with the token found BY SEARCH from a
        // task that execed after the fork — the shape a real handler has.
        "deep" => chain::answer_from_a_grandchild_that_execs(a, tid),
        // The exec half on its own, so a divestment there is distinguishable
        // from a fork that drops the token.
        "execonly" => chain::answer_after_exec(a, &h, tid),
        // A handler that needs one of the REQUESTER's keys reaches it through
        // the token it holds. See `chain`.
        "borrow" => chain::answer_after_borrowing_a_requester_key(a, &h),
        // Name the requester's session keyring by serial, the way the stock
        // handler's `%S` does. See `chain`.
        "sessiondest" => chain::answer_into_requester_session(a, &h),
        _ => instantiate_core(&h, a.key, b"from-helper".to_vec(), 0),
    };
    assert_eq!(rc, 0, "the helper answered the key: {desc}");
    STORE.lock().session.remove(&tid);
    0
}

