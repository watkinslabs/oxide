// `/proc/keys` and `/proc/key-users` content. These assert the FIELDS a reader
// parses (keyutils reads the serial, the flags and the type), and above all
// that the file is filtered per reader rather than dumping every key.

use alloc::vec::Vec;

use super::*;
use super::super::ops::{add_key_core, join_session, revoke_core, set_timeout_core, Ctx};
use super::super::store::{over_quota, quota_limit, set_quota_limit, KeyUser, QuotaKnob, STORE};

fn ctx(tid: u32, uid: u32) -> Ctx {
    Ctx::new(TaskIds { tid, tgid: tid, fsuid: uid, fsgid: uid, groups: Vec::new() }, 0, false)
}

/// The `/proc/keys` line for `serial` as `t` sees it, if any.
fn line_for(t: &Ctx, serial: i64) -> Option<String> {
    let want = format!("{:08x} ", serial as i32);
    proc_keys(&t.t, t.now_ns).lines().find(|l| l.starts_with(&want)).map(String::from)
}

// A key the reader may not VIEW is absent entirely — /proc/keys is a per-task
// view. A global dump would hand every user every other user's serials.
#[test]
fn proc_keys_omits_keys_the_reader_cannot_view() {
    let owner = ctx(4201, 4201);
    let stranger = ctx(4202, 4202);
    let ring = join_session(&owner, None) as i32;
    let k = add_key_core(&owner, "user", "report-private", b"x".to_vec(), true, ring);
    assert!(k > 0);
    assert!(line_for(&owner, k).is_some(), "the owner sees its own key");
    assert!(line_for(&stranger, k).is_none(), "an unrelated uid sees nothing");
}

// The line carries the fields keyutils parses: serial, seven flag characters,
// the timeout word, the perm mask, uid, gid, type name and description.
#[test]
fn proc_keys_line_layout() {
    let t = ctx(4203, 4203);
    let ring = join_session(&t, None) as i32;
    let k = add_key_core(&t, "user", "report-layout", b"abcd".to_vec(), true, ring);
    let line = line_for(&t, k).expect("the owner can view its own key");
    let f: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(f[0], format!("{:08x}", k as i32));
    assert_eq!(f[1].len(), 7, "seven flag characters: {line}");
    assert_eq!(&f[1][0..1], "I", "an instantiated key");
    assert_eq!(&f[1][5..6], "-", "and not a negative one");
    assert_eq!(f[3], "perm", "no timeout set");
    assert_eq!(f[5], "4203", "owned by the caller's fsuid");
    assert_eq!(f[7], "user");
    // The type's describe method appends the payload length.
    assert!(line.ends_with("report-layout: 4"), "{line}");
}

// A keyring reports its member count, and `empty` when it has none — the
// difference `keyctl show` renders as a tree.
#[test]
fn proc_keys_describes_a_keyring_by_member_count() {
    let t = ctx(4204, 4204);
    let ring = join_session(&t, None);
    assert!(line_for(&t, ring).expect("own session keyring").ends_with(": empty"));
    add_key_core(&t, "user", "report-member", b"y".to_vec(), true, ring as i32);
    assert!(line_for(&t, ring).expect("own session keyring").ends_with(": 1"));
}

// Revoking flips the R flag, and a timeout replaces `perm` with the remaining
// time — the two state changes a reader watches for.
#[test]
fn proc_keys_reflects_revocation_and_timeout() {
    let t = ctx(4205, 4205);
    let ring = join_session(&t, None) as i32;
    let k = add_key_core(&t, "user", "report-state", b"z".to_vec(), true, ring);
    assert_eq!(set_timeout_core(&t, k as i32, 30), 0);
    let f: Vec<String> = line_for(&t, k).expect("visible").split_whitespace().map(String::from).collect();
    assert_eq!(f[3], "30s", "the remaining time, not `perm`");
    assert_eq!(revoke_core(&t, k as i32), 0);
    let line = line_for(&t, k).expect("a revoked key is still viewable");
    assert_eq!(&line.split_whitespace().nth(1).expect("flags")[1..2], "R");
}

// An expired key reads `expd` rather than a negative remaining time.
#[test]
fn proc_keys_marks_an_expired_key() {
    let t = ctx(4206, 4206);
    let ring = join_session(&t, None) as i32;
    let k = add_key_core(&t, "user", "report-expired", b"z".to_vec(), true, ring);
    assert_eq!(set_timeout_core(&t, k as i32, 1), 0);
    let later = Ctx::new(t.t.clone(), 5_000_000_000, false);
    let line = line_for(&later, k).expect("still viewable once expired");
    assert_eq!(line.split_whitespace().nth(3), Some("expd"));
}

// /proc/key-users reports the uid's live charge against its ceiling, and the
// charge moves when a key is added.
#[test]
fn proc_key_users_tracks_the_live_charge() {
    let t = ctx(4207, 4207);
    let ring = join_session(&t, None) as i32;
    let before = STORE.lock().key_user(4207);
    add_key_core(&t, "user", "report-quota", b"0123456789".to_vec(), true, ring);
    let after = STORE.lock().key_user(4207);
    assert!(after.nbytes > before.nbytes);
    let want = format!("{:5}: ", 4207);
    let line = proc_key_users().lines().find(|l| l.starts_with(&want))
        .map(String::from).expect("the uid has a line");
    let f: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(f[0], "4207:");
    assert_eq!(f[2].split('/').next(), Some(f[2].split('/').nth(1).expect("nikeys")),
        "every key here is instantiated, so nkeys == nikeys: {line}");
    assert_eq!(f[3], format!("{}/{}", after.nkeys, max_keys(4207)));
    assert_eq!(f[4], format!("{}/{}", after.nbytes, max_bytes(4207)));
}

// Root gets the root ceilings, which is why a system daemon can hold far more
// keys than an ordinary user before EDQUOT.
#[test]
fn proc_key_users_uses_the_root_ceilings_for_uid_zero() {
    let t = ctx(4208, 0);
    let ring = join_session(&t, None) as i32;
    add_key_core(&t, "user", "report-root", b"r".to_vec(), true, ring);
    let line = proc_key_users().lines().find(|l| l.trim_start().starts_with("0:"))
        .map(String::from).expect("uid 0 has a line");
    assert!(line.contains(&format!("/{}", KEY_QUOTA_ROOT_MAXKEYS)), "{line}");
    assert!(line.contains(&format!("/{}", KEY_QUOTA_ROOT_MAXBYTES)), "{line}");
}

// The ceilings are the `/proc/sys/kernel/keys/` knobs, and the knob value is
// what the allocator's ceiling test consumes — a knob that reads back but gates
// nothing is not a sysctl. Proved in two halves so nothing global is disturbed
// for the tests running alongside this one: writing a knob moves what
// `max_keys`/`max_bytes` report, and those are exactly the two numbers
// `over_quota` (the test inside `charge`) decides on.
#[test]
fn the_quota_knobs_are_what_the_allocator_consumes() {
    for (knob, uid, read) in [
        (QuotaKnob::MaxKeys,      4209u32, max_keys as fn(u32) -> u64),
        (QuotaKnob::MaxBytes,     4209,    max_bytes as fn(u32) -> u64),
        (QuotaKnob::RootMaxKeys,  0,       max_keys as fn(u32) -> u64),
        (QuotaKnob::RootMaxBytes, 0,       max_bytes as fn(u32) -> u64),
    ] {
        let saved = quota_limit(knob);
        set_quota_limit(knob, saved + 7);
        assert_eq!(read(uid), saved + 7, "the knob selects the ceiling for this uid");
        set_quota_limit(knob, saved);
        assert_eq!(read(uid), saved);
    }
    // And the ceiling is the gate, not a stored number: a uid already at its
    // key ceiling is refused, and so is one whose next payload crosses the byte
    // ceiling, while a uid under both is allowed.
    let at_ceiling = KeyUser { nkeys: 200, nbytes: 0 };
    assert!(over_quota(&at_ceiling, 0, 200, 20_000), "the 201st key is EDQUOT");
    assert!(!over_quota(&at_ceiling, 0, 201, 20_000), "a higher ceiling admits it");
    let near_bytes = KeyUser { nkeys: 1, nbytes: 19_990 };
    assert!(over_quota(&near_bytes, 11, 200, 20_000), "a payload crossing the byte ceiling is EDQUOT");
    assert!(!over_quota(&near_bytes, 10, 200, 20_000), "one that exactly fits is not");
}
