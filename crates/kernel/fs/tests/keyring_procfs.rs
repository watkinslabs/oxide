// The keyring → procfs binding, end to end: a key created through `keyctl(2)`
// must show up in the bytes procfs hands `/proc/keys`, and a write to the
// `/proc/sys/kernel/keys/*` leaf must move the ceiling `key_alloc` tests.
//
// Both halves cross the crate boundary through the boot-installed hook, which
// is the only place the wiring can silently be absent: a `/proc/keys` bound to
// nothing renders empty and a quota leaf bound to nothing accepts a write and
// changes no ceiling.

use fs::keyring::{quota_limit, set_quota_limit, sys_keyctl, QuotaKnob};
use procfs::proc_handler::{IntHook, ProcHandler};
use syscall::SyscallArgs;

/// `KEYCTL_JOIN_SESSION_KEYRING` — the one key-creating command that takes no
/// user pointer (a NULL name mints an anonymous session keyring), so a hosted
/// test can create a real key without user memory.
const KEYCTL_JOIN_SESSION_KEYRING: u64 = 1;

/// The leaf `/proc/sys/kernel/keys/maxkeys` is registered as: a
/// `proc_dointvec_minmax` over [1, INT_MAX] bound to the store's accessors.
fn maxkeys_leaf() -> IntHook {
    IntHook {
        get: procfs::hooks::keyring::maxkeys,
        set: procfs::hooks::keyring::set_maxkeys,
        bounds: Some(procfs::hooks::keyring::KEY_QUOTA_BOUNDS),
    }
}

#[test]
fn a_new_key_appears_in_the_proc_keys_body_procfs_renders() {
    fs::keyring_procfs::register_procfs_hooks();
    let serial = sys_keyctl(&SyscallArgs { a0: KEYCTL_JOIN_SESSION_KEYRING, ..Default::default() });
    assert!(serial > 0, "joining a session keyring mints one: {serial}");

    let body = String::from_utf8(procfs::hooks::keyring::keys()).expect("ASCII lines");
    let want = format!("{:08x} ", serial as i32);
    assert!(body.lines().any(|l| l.starts_with(&want)),
        "the new key is missing from the /proc/keys body: {body}");
    // The same store answers the crate-local renderer, so the file cannot show
    // a key set that `keyctl(2)` does not.
    assert_eq!(body, fs::keyring::proc_keys());
}

#[test]
fn the_key_users_body_charges_the_owning_uid() {
    fs::keyring_procfs::register_procfs_hooks();
    let serial = sys_keyctl(&SyscallArgs { a0: KEYCTL_JOIN_SESSION_KEYRING, ..Default::default() });
    assert!(serial > 0);
    let body = String::from_utf8(procfs::hooks::keyring::key_users()).expect("ASCII lines");
    assert!(body.lines().any(|l| l.trim_start().starts_with("0:")),
        "no charge line for the creating uid: {body}");
}

#[test]
fn a_sysctl_write_moves_the_ceiling_the_key_store_reports() {
    fs::keyring_procfs::register_procfs_hooks();
    let restore = quota_limit(QuotaKnob::MaxKeys);
    let leaf = maxkeys_leaf();

    leaf.store(b"1234\n").expect("an in-range ceiling is accepted");
    assert_eq!(quota_limit(QuotaKnob::MaxKeys), 1234, "the store's live ceiling moved");
    assert_eq!(leaf.format(), b"1234\n".to_vec(), "and the leaf reads it back");

    // extra1 = 1: a zero ceiling is out of range and must not reach the store.
    assert!(leaf.store(b"0\n").is_err());
    assert_eq!(quota_limit(QuotaKnob::MaxKeys), 1234);

    set_quota_limit(QuotaKnob::MaxKeys, restore);
}
