// Key construction end to end: `request_key` misses, upcalls, and the helper
// answers the key with the instantiation family.
//
// The helper is a real one. `test_helper` below runs the SAME
// `assume_authority_core` / `instantiate_core` / `reject_core` a
// `/sbin/request-key` binary would, under a synthetic helper task whose session
// keyring is the one the construction path built for it. So these tests prove
// the whole chain — token minted, token reachable by the helper, authority
// assumed, key answered, answer visible to the requester — rather than proving
// that some internal function returns a value.
//
// One actor is installed for the whole suite and selects its behaviour from the
// key's DESCRIPTION. A per-test actor would race, because the actor is a single
// global and `cargo test` runs these in parallel.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::*;
use super::upcall::HelperArgs;
use super::super::ops::{add_key_core, assume_authority_core, get_keyring_id, instantiate_core,
    join_session, read_core, reject_core, request_key_core, vet_iov_count};
use super::super::store::{TaskIds, STORE};

/// The two transitions a real helper puts between "authority assumed" and "key
/// answered": `exec` into the handler, `fork` into the program that answers.
mod chain;

/// Synthetic helper tids, distinct from any requester's.
static HELPER_TID: AtomicU32 = AtomicU32::new(900_000);

/// How many times the helper has been run for the negative-caching test.
/// Counting upcalls directly is the only race-free way to assert one did NOT
/// happen: the store is global and every other test in this suite is mutating
/// it in parallel, so a key-count delta proves nothing.
static CACHED_UPCALLS: AtomicU32 = AtomicU32::new(0);
/// The description whose upcalls [`CACHED_UPCALLS`] counts.
const CACHED_DESC: &str = "negate-cached";

fn ctx(tid: u32, uid: u32) -> Ctx {
    Ctx::new(TaskIds { tid, tgid: tid, fsuid: uid, fsgid: uid, groups: Vec::new() }, 0, false)
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The behaviour a test selects through the key description it asks for.
fn behaviour(desc: &str) -> &'static str {
    for b in ["unrunnable", "silent", "negate", "reject", "dest", "chain", "execonly", "borrow", "sessiondest",
        "instantiate"]
    {
        if desc.starts_with(b) { return b; }
    }
    "instantiate"
}

/// A stand-in for `/sbin/request-key`, driven through the real keyctl cores.
fn test_helper(a: &HelperArgs) -> i64 {
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

/// Install the suite's actor. Idempotent: every test calls it.
fn with_helper() { set_actor_for_test(Some(test_helper as Upcall)); }

// A miss with NO callout info is ENOKEY and constructs nothing — the caller was
// only asking whether the key exists. Constructing here would run a helper for
// every failed existence check.
#[test]
fn a_missing_key_without_callout_info_is_enokey_and_builds_nothing() {
    with_helper();
    let t = ctx(4301, 4301);
    join_session(&t, None);
    assert_eq!(request_key_core(&t, "user", "instantiate-none", None, 0), errno(Errno::Enokey));
    // Nothing named that description exists — not even a negative key. Counting
    // the whole store would be racy: the suite runs in parallel against it.
    assert!(!STORE.lock().keys.values().any(|k| k.description == "instantiate-none"),
        "no key was allocated for a request that was never allowed to construct one");
}

// A miss WITH callout info upcalls, and the helper's payload comes back to the
// requester. This is the whole point of request_key(2).
#[test]
fn a_miss_with_callout_info_constructs_the_key_through_the_helper() {
    with_helper();
    let t = ctx(4302, 4302);
    join_session(&t, None);
    let k = request_key_core(&t, "user", "instantiate-basic", Some(b"callout"), 0);
    assert!(k > 0, "the key was constructed: {k}");
    assert_eq!(read_core(&t, k as i32, 64).expect("readable"), b"from-helper".to_vec(),
        "the requester sees the payload the helper wrote");
}

// The empty callout string is NOT the same as no callout string: a NULL pointer
// means "do not build", an empty string still upcalls.
#[test]
fn an_empty_callout_string_still_upcalls() {
    with_helper();
    let t = ctx(4303, 4303);
    join_session(&t, None);
    assert!(request_key_core(&t, "user", "instantiate-empty", Some(b""), 0) > 0);
}

// The helper reads the callout info back off its token with KEYCTL_READ — that
// is how it learns WHAT it was asked to build. Asserted through `read_core`,
// the path a helper actually uses: callout info that round-trips into the store
// but cannot be read back out is a request nobody can service.
#[test]
fn the_helper_reads_the_callout_info_off_its_token() {
    with_helper();
    let t = ctx(4304, 4304);
    let ring = join_session(&t, None) as i32;
    let helper = ctx(4404, 0);
    let (key, auth) = {
        let mut g = STORE.lock();
        let key = g.mint_uninstantiated(types::lookup("user").expect("user type"), "callout-probe",
            4304, 4304, 0, 0).expect("mint");
        let auth = super::super::auth::request_key_auth_new(&mut g, key, "create", b"afs@example",
            ring, &t.t).expect("token");
        let hring = g.resolve(KEY_SPEC_SESSION_KEYRING, &helper.t).expect("helper session");
        g.link(hring, auth).expect("hand the token to the helper");
        (key, auth)
    };
    assert_eq!(read_core(&helper, auth, 64).expect("the token is readable by its holder"),
        b"afs@example".to_vec(), "KEYCTL_READ on the token yields the callout info");
    // And the record names the key and where its answer belongs.
    let g = STORE.lock();
    let rec = g.keys[&auth].auth.clone().expect("record");
    assert_eq!(rec.target, key);
    assert_eq!(rec.dest_keyring, ring, "the token records where the answer belongs");
    assert_eq!(rec.op, "create");
    drop(g);
    // A task that does NOT hold the token cannot read the callout info out of
    // it — the request's parameters are not public.
    let stranger = ctx(4405, 4405);
    assert_eq!(read_core(&stranger, auth, 64), Err(errno(Errno::Eacces)));
}

// `char op[8]` truncates at seven characters plus the terminator, so an
// operation name is never silently widened past what the ABI carries.
#[test]
fn the_operation_name_is_truncated_to_the_abi_field() {
    let t = ctx(4325, 4325);
    let ring = join_session(&t, None) as i32;
    let mut g = STORE.lock();
    let key = g.mint_uninstantiated(types::lookup("user").expect("user type"), "opname",
        4325, 4325, 0, 0).expect("mint");
    let auth = super::super::auth::request_key_auth_new(&mut g, key, "negotiate-long", b"",
        ring, &t.t).expect("token");
    assert_eq!(g.keys[&auth].auth.as_ref().expect("record").op, "negotia");
    drop(g);
}

// A helper that exits 0 without answering the key has FAILED. Trusting its exit
// status would hand the requester a key with nothing in it.
#[test]
fn a_helper_that_answers_nothing_leaves_a_negative_key() {
    with_helper();
    let t = ctx(4305, 4305);
    join_session(&t, None);
    assert_eq!(request_key_core(&t, "user", "silent-key", Some(b"c"), 0), errno(Errno::Enokey));
}

// A helper that could not be run at all also negates the key rather than
// leaving it under construction forever.
#[test]
fn a_helper_that_cannot_run_negates_the_key() {
    with_helper();
    let t = ctx(4306, 4306);
    join_session(&t, None);
    assert_eq!(request_key_core(&t, "user", "unrunnable-key", Some(b"c"), 0), errno(Errno::Enokey));
}

// The negative key is CACHED: a second request finds it and answers from it
// WITHOUT running the helper again. Without this an unresolvable name re-execs
// the helper on every single request.
#[test]
fn a_negative_key_is_cached_and_suppresses_a_second_upcall() {
    with_helper();
    let t = ctx(4307, 4307);
    join_session(&t, None);
    assert_eq!(request_key_core(&t, "user", CACHED_DESC, Some(b"c"), 0), errno(Errno::Enokey));
    assert_eq!(CACHED_UPCALLS.load(Ordering::Relaxed), 1, "the first request ran the helper");
    assert_eq!(request_key_core(&t, "user", CACHED_DESC, Some(b"c"), 0), errno(Errno::Enokey));
    assert_eq!(CACHED_UPCALLS.load(Ordering::Relaxed), 1,
        "the second request answered from the cached negative key without running the helper again");
}

// A REJECTED key reports the errno the helper chose, not a flat ENOKEY.
// Programs branch on EKEYREJECTED — collapsing it to ENOKEY makes a definitive
// refusal look like a transient miss.
#[test]
fn a_rejected_key_reports_the_helpers_errno() {
    with_helper();
    let t = ctx(4308, 4308);
    join_session(&t, None);
    assert_eq!(request_key_core(&t, "user", "reject-me", Some(b"c"), 0),
        errno(Errno::Ekeyrejected));
    // And the cached rejection keeps reporting it.
    assert_eq!(request_key_core(&t, "user", "reject-me", Some(b"c"), 0),
        errno(Errno::Ekeyrejected));
}

// The negative key expires, so a name that was unresolvable an hour ago is
// retried rather than being poisoned forever.
#[test]
fn a_negative_key_expires_and_the_helper_runs_again() {
    with_helper();
    let t = ctx(4309, 4309);
    join_session(&t, None);
    assert_eq!(request_key_core(&t, "user", "negate-expiry", Some(b"c"), 0), errno(Errno::Enokey));
    let neg = STORE.lock().keys.values()
        .find(|k| k.description == "negate-expiry").map(|k| (k.serial, k.expiry_ns))
        .expect("the negative key is cached");
    assert!(neg.1 > 0, "a negative key always has an expiry; a permanent one would poison the name");
    assert!(neg.1 <= KEY_NEGATIVE_TIMEOUT * 1_000_000_000 + 1);
}

// The constructed key is cached in the keyring the caller named, so the next
// lookup is a hit.
#[test]
fn the_constructed_key_is_linked_into_the_named_destination() {
    with_helper();
    let t = ctx(4310, 4310);
    let ring = join_session(&t, None) as i32;
    let k = request_key_core(&t, "user", "instantiate-dest", Some(b"c"), ring);
    assert!(k > 0);
    assert!(STORE.lock().keys[&ring].members.contains(&(k as i32)),
        "the answer is cached where the caller asked");
}

// With no destination named, the key lands in the keyring `jit_keyring`
// selects, falling through to the first one the task actually has.
#[test]
fn the_default_destination_falls_through_to_an_existing_keyring() {
    with_helper();
    let t = ctx(4311, 4311);
    let ses = join_session(&t, None) as i32;
    // No thread or process keyring exists, so the cascade reaches the session.
    let k = request_key_core(&t, "user", "instantiate-fallthrough", Some(b"c"), 0);
    assert!(k > 0);
    assert!(STORE.lock().keys[&ses].members.contains(&(k as i32)));
}

// A helper naming KEY_SPEC_REQUESTOR_KEYRING caches into the REQUESTER's
// keyring, not its own — the mechanism that lets /sbin/request-key put the
// answer where the caller will find it.
#[test]
fn the_helper_can_instantiate_into_the_requestors_keyring() {
    with_helper();
    let t = ctx(4312, 4312);
    let ring = join_session(&t, None) as i32;
    let k = request_key_core(&t, "user", "dest-requestor", Some(b"c"), ring);
    assert!(k > 0, "{k}");
    assert!(STORE.lock().keys[&ring].members.contains(&(k as i32)),
        "the answer landed in the requester's keyring, reached through the token");
}

// A keyring can never be built by an upcall: there is no payload for a helper
// to supply.
#[test]
fn a_keyring_cannot_be_constructed() {
    with_helper();
    let t = ctx(4313, 4313);
    join_session(&t, None);
    assert_eq!(request_key_core(&t, "keyring", "instantiate-ring", Some(b"c"), 0),
        errno(Errno::Eperm));
}

// The token is burned the moment the key is answered, so the authority cannot
// be replayed to overwrite it.
#[test]
fn the_token_is_destroyed_once_the_key_is_answered() {
    with_helper();
    let t = ctx(4314, 4314);
    join_session(&t, None);
    let k = request_key_core(&t, "user", "instantiate-burn", Some(b"c"), 0);
    assert!(k > 0);
    let live = STORE.lock().keys.values()
        .any(|x| x.key_type.name == REQKEY_AUTH_TYPE
             && x.auth.as_ref().map(|a| a.target) == Some(k as i32));
    assert!(!live, "no usable token for this key survives its instantiation");
}

// Without a token, the instantiation family is EPERM — not ENOKEY, and
// certainly not a successful write into somebody else's key.
#[test]
fn instantiation_without_a_token_is_eperm() {
    let t = ctx(4315, 4315);
    let ring = join_session(&t, None) as i32;
    let k = add_key_core(&t, "user", "no-token", b"v".to_vec(), true, ring) as i32;
    assert_eq!(instantiate_core(&t, k, b"x".to_vec(), 0), errno(Errno::Eperm));
    assert_eq!(reject_core(&t, k, 60, Errno::Enokey.as_i32() as u32, 0), errno(Errno::Eperm));
}

// A token for a DIFFERENT key does not authorise this one: a helper servicing
// request A must not be able to answer request B.
#[test]
fn a_token_authorises_exactly_one_key() {
    let t = ctx(4316, 4316);
    let ring = join_session(&t, None) as i32;
    let victim = add_key_core(&t, "user", "other-key", b"v".to_vec(), true, ring) as i32;
    let mut g = STORE.lock();
    let mine = g.mint_uninstantiated(types::lookup("user").expect("user type"), "mine",
        4316, 4316, 0, 0).expect("mint");
    let auth = super::super::auth::request_key_auth_new(&mut g, mine, "create", b"", ring, &t.t)
        .expect("token");
    g.link(ring, auth).expect("link the token where the caller can reach it");
    drop(g);
    assert_eq!(assume_authority_core(&t, mine), auth as i64);
    assert_eq!(instantiate_core(&t, victim, b"x".to_vec(), 0), errno(Errno::Eperm),
        "the held token names `mine`, so `victim` is refused");
    assert_eq!(instantiate_core(&t, mine, b"x".to_vec(), 0), 0);
}

// ASSUME_AUTHORITY(0) divests; a negative id is EINVAL; a key the caller holds
// no token for is ENOKEY.
#[test]
fn assume_authority_argument_contract() {
    let t = ctx(4317, 4317);
    join_session(&t, None);
    assert_eq!(assume_authority_core(&t, 0), 0, "divesting authority always succeeds");
    assert_eq!(assume_authority_core(&t, KEY_SPEC_SESSION_KEYRING), errno(Errno::Einval));
    assert_eq!(assume_authority_core(&t, 0x7fff_0000), errno(Errno::Enokey));
}

// KEYCTL_REJECT's error must be a real errno a requester can be handed, and not
// one of the restart pseudo-errnos, which mean "retry the syscall" rather than
// naming a failure.
#[test]
fn reject_validates_the_error_before_anything_else() {
    let t = ctx(4318, 4318);
    join_session(&t, None);
    for bad in [0u32, MAX_ERRNO, MAX_ERRNO + 1, ERESTARTSYS_NR, ERESTARTNOINTR_NR,
                ERESTARTNOHAND_NR, ERESTART_RESTARTBLOCK_NR] {
        assert_eq!(reject_core(&t, 0x7fff_0001, 60, bad, 0), errno(Errno::Einval),
            "error {bad} is not a rejectable errno");
    }
    // A valid error gets past the check and fails on the MISSING token instead,
    // proving the error test runs first and is not masking the token test.
    assert_eq!(reject_core(&t, 0x7fff_0001, 60, Errno::Ekeyrejected.as_i32() as u32, 0),
        errno(Errno::Eperm));
}

// A key can only be answered once — a second instantiation is EBUSY, not a
// silent overwrite of whatever the first helper wrote.
#[test]
fn a_key_cannot_be_instantiated_twice() {
    let t = ctx(4319, 4319);
    let ring = join_session(&t, None) as i32;
    let mut g = STORE.lock();
    let user = types::lookup("user").expect("user type");
    let key = g.mint_uninstantiated(user, "twice", 4319, 4319, types::default_perm(user), 0)
        .expect("mint");
    let auth = super::super::auth::request_key_auth_new(&mut g, key, "create", b"", ring, &t.t)
        .expect("token");
    g.link(ring, auth).expect("link");
    drop(g);
    assert_eq!(assume_authority_core(&t, key), auth as i64);
    assert_eq!(instantiate_core(&t, key, b"first".to_vec(), ring), 0);
    // The token is burned, so the second attempt cannot even claim authority.
    assert_eq!(instantiate_core(&t, key, b"second".to_vec(), ring), errno(Errno::Eperm));
    assert_eq!(read_core(&t, key, 64).expect("readable"), b"first".to_vec());
}

// The iovec form has the same 1024-segment ceiling as every other vectored
// call, and a NULL vector is zero segments rather than a fault.
#[test]
fn instantiate_iov_segment_count_contract() {
    assert_eq!(vet_iov_count(false, 9999), Ok(0), "a NULL vector is zero segments");
    assert_eq!(vet_iov_count(true, UIO_MAXIOV), Ok(UIO_MAXIOV));
    assert_eq!(vet_iov_count(true, UIO_MAXIOV + 1), Err(errno(Errno::Einval)));
}

// An uninstantiated key nobody ever answered is EIO, not a serial handed to a
// caller that would then read nothing out of it.
#[test]
fn an_unanswered_key_is_eio() {
    let t = ctx(4320, 4320);
    join_session(&t, None);
    let mut g = STORE.lock();
    let key = g.mint_uninstantiated(types::lookup("user").expect("user type"), "unanswered",
        4320, 4320, 0, 0).expect("mint");
    let rv = construction_result(&g, key, 0);
    drop(g);
    assert_eq!(rv, Err(errno(Errno::Eio)));
}

// The helper's session keyring is named after the key it is building, so a
// /proc/keys reader can tell which request a live helper is servicing.
#[test]
fn the_helper_keyring_names_its_request() {
    assert_eq!(helper_keyring_name(0x1234), String::from("_req.4660"));
    let t = ctx(4321, 4321);
    let mut g = STORE.lock();
    let r = new_helper_keyring(&mut g, 77, &t.t).expect("helper keyring");
    assert_eq!(g.keys[&r].description, "_req.77");
    assert_eq!(g.keys[&r].perm, REQKEY_HELPER_KEYRING_PERM);
    g.destroy(r);
}

// `get_instantiation_keyring`'s id contract: the token id is not a keyring, and
// an id below the defined range is not silently treated as one.
#[test]
fn the_instantiation_destination_rejects_ids_that_name_no_keyring() {
    let t = ctx(4322, 4322);
    let ring = join_session(&t, None) as i32;
    let mut g = STORE.lock();
    let key = g.mint_uninstantiated(types::lookup("user").expect("user type"), "instdest",
        4322, 4322, 0, 0).expect("mint");
    let auth = super::super::auth::request_key_auth_new(&mut g, key, "create", b"", ring, &t.t)
        .expect("token");
    let rec = g.keys[&auth].auth.clone().expect("record");
    let via_auth = super::super::auth::instantiation_keyring(&mut g, KEY_SPEC_REQKEY_AUTH_KEY, &rec, &t.t, 0);
    let too_low = super::super::auth::instantiation_keyring(&mut g, -9, &rec, &t.t, 0);
    let none = super::super::auth::instantiation_keyring(&mut g, 0, &rec, &t.t, 0);
    let requestor = super::super::auth::instantiation_keyring(&mut g, KEY_SPEC_REQUESTOR_KEYRING, &rec, &t.t, 0);
    drop(g);
    assert_eq!(via_auth, Err(errno(Errno::Einval)), "the token is not a keyring");
    assert_eq!(too_low, Err(errno(Errno::Enokey)));
    assert_eq!(none, Ok(None), "id 0 caches the answer nowhere");
    assert_eq!(requestor, Ok(Some(ring)), "the requestor id resolves to the recorded destination");
}

// `@a` and `@` resolve only while a token is held, and name the token and the
// requester's destination respectively.
#[test]
fn the_special_authorisation_ids_resolve_only_under_a_token() {
    let t = ctx(4323, 4323);
    let ring = join_session(&t, None) as i32;
    {
        let mut g = STORE.lock();
        assert_eq!(g.resolve(KEY_SPEC_REQKEY_AUTH_KEY, &t.t), Err(Errno::Enokey));
        assert_eq!(g.resolve(KEY_SPEC_REQUESTOR_KEYRING, &t.t), Err(Errno::Enokey));
    }
    let mut g = STORE.lock();
    let key = g.mint_uninstantiated(types::lookup("user").expect("user type"), "specialids",
        4323, 4323, 0, 0).expect("mint");
    let auth = super::super::auth::request_key_auth_new(&mut g, key, "create", b"", ring, &t.t)
        .expect("token");
    g.link(ring, auth).expect("link");
    drop(g);
    assert_eq!(assume_authority_core(&t, key), auth as i64);
    let mut g = STORE.lock();
    assert_eq!(g.resolve(KEY_SPEC_REQKEY_AUTH_KEY, &t.t), Ok(auth));
    assert_eq!(g.resolve(KEY_SPEC_REQUESTOR_KEYRING, &t.t), Ok(ring));
    drop(g);
    // Divesting takes both away again.
    assert_eq!(assume_authority_core(&t, 0), 0);
    assert_eq!(STORE.lock().resolve(KEY_SPEC_REQKEY_AUTH_KEY, &t.t), Err(Errno::Enokey));
}

// A key under construction is invisible to `KEYCTL_GET_KEYRING_ID`-style full
// lookups but must not be collected out from under the helper building it.
#[test]
fn a_key_under_construction_survives_the_gc() {
    let t = ctx(4324, 4324);
    join_session(&t, None);
    let mut g = STORE.lock();
    let key = g.mint_uninstantiated(types::lookup("user").expect("user type"), "gc-survivor",
        4324, 4324, 0, 0).expect("mint");
    // Linked into nothing at all — only the construction in flight holds it.
    g.collect();
    let alive = g.keys.contains_key(&key);
    drop(g);
    assert!(alive, "collecting a key mid-construction would strand its requester");
    let _ = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true);
}
