// The per-uid `key_user` quota: `qnkeys`/`qnbytes` against maxkeys/maxbytes,
// EDQUOT, the update-time byte delta, and the refund a collected key makes.
// Each test uses a UNIQUE uid so the process-global quota tree never collides.

use super::*;
use super::super::ops::*;
use super::super::store::{max_bytes, max_keys};
use super::super::uapi::{KEY_QUOTA_MAXBYTES, KEY_QUOTA_MAXKEYS,
    KEY_QUOTA_ROOT_MAXBYTES, KEY_QUOTA_ROOT_MAXKEYS, ROOT_UID};

fn edquot() -> i64 { err(Errno::Edquot) }

fn charge(uid: u32) -> (u64, u64) {
    let u = STORE.lock().key_user(uid);
    (u.nkeys, u.nbytes)
}

// Root gets the far higher ceilings; every other uid gets the general ones.
#[test]
fn root_has_its_own_quota_ceilings() {
    assert_eq!(max_keys(ROOT_UID), KEY_QUOTA_ROOT_MAXKEYS);
    assert_eq!(max_bytes(ROOT_UID), KEY_QUOTA_ROOT_MAXBYTES);
    assert_eq!(max_keys(1000), KEY_QUOTA_MAXKEYS);
    assert_eq!(max_bytes(1000), KEY_QUOTA_MAXBYTES);
    assert!(KEY_QUOTA_ROOT_MAXKEYS > KEY_QUOTA_MAXKEYS);
    assert!(KEY_QUOTA_ROOT_MAXBYTES > KEY_QUOTA_MAXBYTES);
}

// A key is charged `strlen(desc) + 1 + <payload quota>` bytes plus one key
// against its OWNER's uid — the fsuid, not the caller's real uid.
#[test]
fn a_new_key_charges_description_plus_payload() {
    let t = ctx(4001, 7001);
    // Take the baseline AFTER the session keyring exists, since that keyring
    // is itself charged.
    let _ = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true);
    let before = charge(7001);
    let serial = add_key_core(&t, "user", "abcd", alloc::vec![1, 2, 3], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert!(serial > 0);
    let after = charge(7001);
    // "abcd" is 4 bytes + the NUL + a 3-byte payload.
    assert_eq!(after.1 - before.1, 4 + 1 + 3);
    assert_eq!(after.0 - before.0, 1);
}

// The implicit session keyring is itself charged: keys are not free just
// because the kernel created them on the task's behalf.
#[test]
fn implicit_keyrings_are_charged_too() {
    let t = ctx(4002, 7002);
    assert_eq!(charge(7002), (0, 0));
    let _ = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true);
    assert_eq!(charge(7002).0, 1, "the lazily created session keyring is charged");
}

// Crossing the key-COUNT ceiling is EDQUOT, and the refusal does not consume
// the slot: the count sits exactly at the ceiling afterwards.
#[test]
fn exceeding_the_key_count_ceiling_is_edquot() {
    let t = ctx(4003, 7003);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let mut minted = 0u64;
    // Descriptions stay short so the BYTE ceiling is not the one that trips.
    while charge(7003).0 < KEY_QUOTA_MAXKEYS {
        let d = alloc::format!("q{}", minted);
        let rv = add_key_core(&t, "user", &d, alloc::vec![1], true, ring);
        assert!(rv > 0, "unexpected early refusal at {} keys: {}", minted, rv);
        minted += 1;
    }
    assert_eq!(charge(7003).0, KEY_QUOTA_MAXKEYS);
    assert_eq!(add_key_core(&t, "user", "one-too-many", alloc::vec![1], true, ring), edquot());
    assert_eq!(charge(7003).0, KEY_QUOTA_MAXKEYS, "a refused mint charges nothing");
}

// Crossing the key-BYTE ceiling is EDQUOT even when the key count is far
// below its own ceiling.
#[test]
fn exceeding_the_byte_ceiling_is_edquot() {
    let t = ctx(4004, 7004);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    // Each key carries a payload big enough that ~11 of them cross 20000
    // bytes, well inside the 200-key ceiling.
    let big = alloc::vec![0u8; 2000];
    let mut minted = 0u64;
    loop {
        let d = alloc::format!("b{}", minted);
        let rv = add_key_core(&t, "user", &d, big.clone(), true, ring);
        if rv == edquot() { break; }
        assert!(rv > 0, "unexpected error {}", rv);
        minted += 1;
        assert!(minted < KEY_QUOTA_MAXKEYS, "the byte ceiling should trip first");
    }
    assert!(charge(7004).1 + 2000 > KEY_QUOTA_MAXBYTES);
}

// Growing a key's payload re-reserves the delta and can EDQUOT; shrinking it
// always succeeds and hands the bytes back.
#[test]
fn update_moves_the_byte_charge_by_the_delta() {
    let t = ctx(4005, 7005);
    let k = add_key_core(&t, "user", "delta", alloc::vec![0u8; 100], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let base = charge(7005).1;
    let keys_before = charge(7005).0;
    assert_eq!(update_core(&t, k, alloc::vec![0u8; 300], true), 0);
    assert_eq!(charge(7005).1, base + 200, "growing charges the delta");
    assert_eq!(update_core(&t, k, alloc::vec![0u8; 50], true), 0);
    assert_eq!(charge(7005).1, base - 50, "shrinking refunds the delta");
    assert_eq!(charge(7005).0, keys_before, "the key COUNT never moves on update");
}

// An update that would cross the byte ceiling is EDQUOT and leaves BOTH the
// payload and the charge untouched.
#[test]
fn an_update_past_the_byte_ceiling_is_edquot() {
    let t = ctx(4006, 7006);
    let k = add_key_core(&t, "user", "grow", alloc::vec![1, 2, 3], true, KEY_SPEC_SESSION_KEYRING) as i32;
    // Fill most of the byte quota with other keys, then try to grow this one
    // past what is left.
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let mut i = 0;
    while charge(7006).1 < KEY_QUOTA_MAXBYTES - 8000 {
        let d = alloc::format!("f{}", i);
        assert!(add_key_core(&t, "user", &d, alloc::vec![0u8; 2000], true, ring) > 0);
        i += 1;
    }
    let charged = charge(7006);
    assert_eq!(update_core(&t, k, alloc::vec![0u8; 30000], true), edquot());
    assert_eq!(charge(7006), charged, "a refused update moves no charge");
    assert_eq!(read_core(&t, k, 0), Ok(alloc::vec![1, 2, 3]), "and leaves the payload alone");
}

// Losing its last link kills a key: the gc collects it and hands its whole
// charge — key AND bytes — back to its owner.
#[test]
fn unlinking_the_last_link_refunds_the_charge() {
    let t = ctx(4007, 7007);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let before = charge(7007);
    let k = add_key_core(&t, "user", "transient", alloc::vec![0u8; 500], true, ring) as i32;
    assert!(charge(7007).1 > before.1);
    assert_eq!(unlink_core(&t, k, ring), 0);
    assert_eq!(charge(7007), before, "the collected key's charge is refunded in full");
    assert_eq!(read_core(&t, k, 0), Err(enokey()), "and the serial is gone");
}

// A key with a SECOND link survives losing the first, and keeps its charge.
#[test]
fn a_second_link_keeps_the_key_and_its_charge_alive() {
    let t = ctx(4008, 7008);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let stash = add_key_core(&t, "keyring", "stash", alloc::vec![], false, ring) as i32;
    let k = add_key_core(&t, "user", "two-links", alloc::vec![9], true, ring) as i32;
    assert_eq!(link_core(&t, k, stash), 0);
    let held = charge(7008);
    assert_eq!(unlink_core(&t, k, ring), 0);
    assert_eq!(charge(7008), held, "still linked from the stash, so still charged");
    assert_eq!(read_core(&t, k, 0), Ok(alloc::vec![9]));
    assert_eq!(unlink_core(&t, k, stash), 0);
    assert!(charge(7008).0 < held.0, "the last link going away refunds it");
}

// INVALIDATE also collects the key and refunds it.
#[test]
fn invalidate_refunds_the_charge() {
    let t = ctx(4009, 7009);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let before = charge(7009);
    let k = add_key_core(&t, "user", "doomed", alloc::vec![0u8; 400], true, ring) as i32;
    assert_eq!(invalidate_core(&t, k), 0);
    assert_eq!(charge(7009), before);
}

// Clearing a keyring collects every member it held.
#[test]
fn clearing_a_keyring_refunds_its_members() {
    let t = ctx(4010, 7010);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let stash = add_key_core(&t, "keyring", "clear-me", alloc::vec![], false, ring) as i32;
    let held = charge(7010);
    for i in 0..5 {
        let d = alloc::format!("member{}", i);
        assert!(add_key_core(&t, "user", &d, alloc::vec![0u8; 100], true, stash) > 0);
    }
    assert_eq!(charge(7010).0, held.0 + 5);
    assert_eq!(clear_core(&t, stash), 0);
    assert_eq!(charge(7010), held, "every collected member is refunded");
}

// The quota is per-OWNER: one uid exhausting its quota does not touch another
// uid's, and ownership follows the fsuid the key was minted under.
#[test]
fn the_quota_is_per_owner_uid() {
    let a = ctx(4011, 7011);
    let b = ctx(4012, 7012);
    assert!(add_key_core(&a, "user", "mine", alloc::vec![0u8; 700], true, KEY_SPEC_SESSION_KEYRING) > 0);
    let ca = charge(7011);
    let cb = charge(7012);
    assert!(ca.1 >= 700);
    assert!(cb.1 < 700, "the other uid is untouched");
    assert!(add_key_core(&b, "user", "theirs", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) > 0);
    assert_eq!(charge(7011), ca, "and still untouched after b mints its own");
}
