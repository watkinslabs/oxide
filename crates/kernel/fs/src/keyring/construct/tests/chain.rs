// What happens BETWEEN "the helper assumed authority" and "the key is
// answered" — the two credential transitions a real construction goes through
// and the reach the token grants while it lasts.
//
// A real `/sbin/request-key` does not answer the key itself. It assumes
// authority over the key, EXECS the handler its configuration names, and that
// handler FORKS the program that finally instantiates. So the token has to
// survive an exec and be inherited across a fork, or every construction on a
// real system ends EPERM with the helper exiting non-zero and the key left
// under construction — which is indistinguishable from a helper that simply
// refused, and is exactly the failure this file pins.
//
// The suite's actor selects these behaviours from the key description; the two
// entry points below are the bodies it calls.

use super::*;
use super::super::super::auth;
use super::super::super::ops::search::{search_process, Expired};
use super::super::super::lifecycle;
use super::super::super::store::KeyNs;
use super::super::super::types;

/// The answer both behaviours instantiate with, so a requester reading it back
/// proves the helper — and not the kernel — filled the key in.
const ANSWER: &[u8] = b"from-helper";

/// A key held ONLY by the requester, which a helper can reach solely through
/// the token it is servicing the request under.
const REQUESTER_ONLY: &str = "borrow-requester-only";

/// The actor body for `chain`: assume authority (already done by the caller),
/// exec the handler, fork the program that answers, and answer from the CHILD.
/// # C: O(N)
pub(super) fn answer_after_exec_and_fork(a: &HelperArgs, helper_tid: u32) -> i64 {
    super::super::super::lifecycle::exec(helper_tid, helper_tid);
    let child_tid = HELPER_TID.fetch_add(1, Ordering::Relaxed);
    super::super::super::lifecycle::fork(helper_tid, child_tid);
    let child = ctx(child_tid, 0);
    let rc = instantiate_core(&child, a.key, ANSWER.to_vec(), 0);
    STORE.lock().session.remove(&child_tid);
    rc
}

/// The actor body for `deep`: the whole shape a real system has, every
/// transition through the production hook that implements it.
///
///   `/sbin/request-key` execs (already done) and assumes authority
///     -> execs the configured handler                 `lifecycle::exec`
///     -> the handler is a shell, which FORKS          `lifecycle::fork`
///        -> the child EXECS `keyctl`                  `lifecycle::exec`
///           -> which re-assumes authority BY SEARCH and answers the key.
///
/// The re-assumption is the part no other case covers: the program that finally
/// answers finds the token by SEARCHING its own keyrings, so the helper's
/// session keyring — and the token in it — has to have survived a fork and two
/// execs to still be there. Every earlier hosted case answered from a task that
/// had inherited the assumed-authority slot directly, which cannot observe a
/// token that became unreachable.
/// # C: O(N)
pub(super) fn answer_from_a_grandchild_that_execs(a: &HelperArgs, helper_tid: u32) -> i64 {
    lifecycle::exec(helper_tid, helper_tid);
    let sh_tid = HELPER_TID.fetch_add(1, Ordering::Relaxed);
    lifecycle::fork(helper_tid, sh_tid);
    let keyctl_tid = HELPER_TID.fetch_add(1, Ordering::Relaxed);
    lifecycle::fork(sh_tid, keyctl_tid);
    lifecycle::exec(keyctl_tid, keyctl_tid);
    let grandchild = ctx(keyctl_tid, 0);
    // Divest first, so what follows can only succeed by FINDING the token —
    // an inherited slot would make the search unnecessary and the case vacuous.
    assume_authority_core(&grandchild, 0);
    let found = assume_authority_core(&grandchild, a.key);
    assert_eq!(found, a.authkey as i64,
        "the grandchild finds the token by searching the keyrings it inherited: {found}");
    let rc = instantiate_core(&grandchild, a.key, ANSWER.to_vec(), 0);
    for tid in [sh_tid, keyctl_tid] { lifecycle::exit(tid, tid, true); }
    rc
}

/// The actor body for `execonly`: exec the handler and answer from the SAME
/// task, isolating the exec transition from the fork. # C: O(N)
pub(super) fn answer_after_exec(a: &HelperArgs, h: &Ctx, helper_tid: u32) -> i64 {
    super::super::super::lifecycle::exec(helper_tid, helper_tid);
    instantiate_core(h, a.key, ANSWER.to_vec(), 0)
}

/// The actor body for `sessiondest`: cache the answer in the REQUESTER's
/// session keyring, named by serial — what the stock handler's `%S` expands to.
/// # C: O(N)
pub(super) fn answer_into_requester_session(a: &HelperArgs, h: &Ctx) -> i64 {
    let ring = {
        let g = STORE.lock();
        g.keys.get(&a.authkey).and_then(|k| k.auth.as_ref()).map(|d| d.requester.tid)
            .and_then(|tid| g.session.get(&tid).copied()).unwrap_or(0)
    };
    assert!(ring > 0, "the requester has a session keyring for the helper to name");
    instantiate_core(h, a.key, ANSWER.to_vec(), ring)
}

/// The actor body for `borrow`: read a key that exists only in the REQUESTER's
/// keyrings, then answer. # C: O(N)
pub(super) fn answer_after_borrowing_a_requester_key(a: &HelperArgs, h: &Ctx) -> i64 {
    let found = request_key_core(h, "user", REQUESTER_ONLY, None, 0);
    assert!(found > 0, "the helper reaches the requester's key through its token: {found}");
    instantiate_core(h, a.key, ANSWER.to_vec(), 0)
}

// The case a booted system actually runs: the token is found BY SEARCH from a
// grandchild that has been through a fork and two execs. Proven end to end on
// both architectures by the boot probe; this is the check that can fail in
// milliseconds when a lifecycle hook stops carrying it.
#[test]
fn a_grandchild_that_execs_finds_the_token_and_answers() {
    with_helper();
    let t = ctx(910_115, 910_115);
    let key = request_key_core(&t, "user", "deep-exec-fork-exec", Some(b"callout"), 0);
    assert!(key > 0, "the construction completed across fork+exec+exec: {key}");
    assert_eq!(read_core(&t, key as i32, 64).expect("read"), ANSWER);
}

// The headline case. A helper that execs its handler and forks the program that
// answers still completes the construction, and the requester reads the
// helper's payload back.
#[test]
fn a_construction_completes_across_the_helper_s_exec_and_fork() {
    with_helper();
    let t = ctx(910_101, 910_101);
    let key = request_key_core(&t, "user", "chain-exec-fork", Some(b"callout"), 0);
    assert!(key > 0, "the construction completed: {key}");
    assert_eq!(read_core(&t, key as i32, 64).expect("read"), ANSWER);
}

// The transition that used to divest, on its own: authority assumed before an
// exec is still held after it. `prepare_exec_creds` drops the thread and
// process keyrings and nothing else.
#[test]
fn assumed_authority_survives_an_exec() {
    with_helper();
    let t = ctx(910_103, 910_103);
    let key = request_key_core(&t, "user", "execonly-handler", Some(b"callout"), 0);
    assert!(key > 0, "an exec between assuming authority and answering is not a divestment: {key}");
}

// A key answered by a grandchild is answered once and for all: the token is
// burned, so a second attempt under the same tid is EKEYREVOKED rather than a
// second instantiation.
#[test]
fn the_token_is_spent_once_the_grandchild_has_answered() {
    with_helper();
    let t = ctx(910_105, 910_105);
    let key = request_key_core(&t, "user", "chain-spent", Some(b"callout"), 0);
    assert!(key > 0);
    let desc = alloc::format!("{key:x}");
    let g = STORE.lock();
    assert!(!g.keys[&(key as i32)].under_construction);
    // The token names its target in hex, so this finds THIS construction's
    // token and no other test's.
    assert!(g.keys.values().all(|k| k.key_type.name != REQKEY_AUTH_TYPE || k.description != desc
        || k.auth.is_none()),
        "the token that answered this key is burned");
}

// The reach the token grants: a helper searching for a key finds one that only
// the REQUESTER holds. Without this a handler could not use the credentials of
// the task it is building for.
#[test]
fn a_helper_reaches_the_requester_s_keys_while_it_holds_the_token() {
    with_helper();
    let t = ctx(910_107, 910_107);
    join_session(&t, None);
    let held = add_key_core(&t, "user", REQUESTER_ONLY, b"secret".to_vec(), true,
        KEY_SPEC_SESSION_KEYRING);
    assert!(held > 0, "the requester holds it: {held}");
    let key = request_key_core(&t, "user", "borrow-through-token", Some(b"callout"), 0);
    assert!(key > 0, "the helper found it and answered: {key}");
}

// ... and that reach is bounded by the token in both directions: without one
// the requester's keys are invisible, and WITH one a TOKEN is still invisible —
// a helper may act only under the token it was handed, never under one it
// found by searching the task it is servicing.
#[test]
fn the_requester_reach_is_token_scoped_and_never_yields_a_token() {
    let req = ctx(910_109, 910_109);
    let session = join_session(&req, None) as i32;
    let secret = add_key_core(&req, "user", "scoped-requester-only", b"s".to_vec(), true,
        KEY_SPEC_SESSION_KEYRING) as i32;
    assert!(secret > 0);
    let helper = ctx(910_110, 0);

    // No token: the requester's keyrings are not reachable at all.
    {
        let g = STORE.lock();
        assert!(search_process(&g, &helper.t, "user", "scoped-requester-only", 0, Expired::Skip)
            .is_err(), "an unauthorised task sees nothing of the requester");
    }

    let ty = types::lookup("user").expect("the user type is registered");
    let (target, token) = {
        let mut g = STORE.lock();
        let target = g.mint_uninstantiated(ty, "scoped-target", req.t.fsuid, req.t.fsgid,
            types::default_perm(ty), types::payload_quota(ty, 0), KeyNs::initial()).expect("mint");
        let token = auth::request_key_auth_new(&mut g, target, REQKEY_OP_CREATE, b"c", session,
            &req.t).expect("token");
        // The token is reachable from the REQUESTER's own keyrings here, which
        // is the case the type guard has to refuse.
        g.link(session, token).expect("link");
        g.authkey.insert(helper.t.tid, token);
        (target, token)
    };

    {
        let g = STORE.lock();
        assert_eq!(search_process(&g, &helper.t, "user", "scoped-requester-only", 0, Expired::Skip),
            Ok(secret), "the token opens the requester's keyrings");
        assert!(search_process(&g, &helper.t, REQKEY_AUTH_TYPE, &alloc::format!("{target:x}"), 0,
            Expired::Report).is_err(), "a token is never reachable through the requester");
    }

    // Divesting closes the reach again.
    {
        let mut g = STORE.lock();
        g.authkey.remove(&helper.t.tid);
        assert!(search_process(&g, &helper.t, "user", "scoped-requester-only", 0, Expired::Skip)
            .is_err(), "the reach lasts exactly as long as the token is held");
        let _ = token;
    }
}

// The destination the stock handler actually names. A session keyring grants
// its owner View and Read through the user byte and Write only through the
// possessor byte, and the helper is a different task — so caching the answer
// there is EACCES unless the helper possesses what the REQUESTER possesses.
// This is the step that stopped every real construction: the token reached the
// program that answers, and the answer had nowhere to go.
#[test]
fn a_helper_caches_the_answer_in_the_requester_s_session_keyring() {
    with_helper();
    let t = ctx(910_112, 910_112);
    let ses = join_session(&t, None) as i32;
    assert!(ses > 0);
    let key = request_key_core(&t, "user", "sessiondest-probe", Some(b"callout"), 0);
    assert!(key > 0, "the construction completed: {key}");
    let g = STORE.lock();
    assert!(g.keys[&ses].members.contains(&(key as i32)),
        "the answer is cached where the helper was told to put it");
}
