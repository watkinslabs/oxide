// The boot binding that hands procfs the keyring's `/proc/keys`,
// `/proc/key-users` and `/proc/sys/kernel/keys/*` accessors.
//
// procfs is the leaf crate this one depends on, so the direction has to be an
// install rather than a call. What is installed are the SAME functions the
// syscall paths use, so no file here can report a key set `keyctl(2)` does not
// see or a ceiling `key_alloc` does not test.
//

use alloc::vec::Vec;

use super::{persistent_expiry, proc_key_users, proc_keys, quota_limit,
    set_persistent_expiry, set_quota_limit, QuotaKnob};

/// Rendered per read, in the READING task's context — `proc_keys` filters by
/// what that task may VIEW. # C: O(N)
fn keys_body() -> Vec<u8> { proc_keys().into_bytes() }
/// # C: O(N)
fn key_users_body() -> Vec<u8> { proc_key_users().into_bytes() }

/// `proc_dointvec_minmax` keeps a stored ceiling inside [1, INT_MAX], so the
/// cast back to the store's unsigned ceiling cannot lose a written value.
fn get(k: QuotaKnob) -> i64 { quota_limit(k) as i64 }
fn set(k: QuotaKnob, v: i64) { set_quota_limit(k, v.max(0) as u64) }

fn maxkeys() -> i64 { get(QuotaKnob::MaxKeys) }
fn set_maxkeys(v: i64) { set(QuotaKnob::MaxKeys, v) }
fn maxbytes() -> i64 { get(QuotaKnob::MaxBytes) }
fn set_maxbytes(v: i64) { set(QuotaKnob::MaxBytes, v) }
fn root_maxkeys() -> i64 { get(QuotaKnob::RootMaxKeys) }
fn set_root_maxkeys(v: i64) { set(QuotaKnob::RootMaxKeys, v) }
fn root_maxbytes() -> i64 { get(QuotaKnob::RootMaxBytes) }
fn set_root_maxbytes(v: i64) { set(QuotaKnob::RootMaxBytes, v) }
fn expiry() -> i64 { persistent_expiry() as i64 }
fn set_expiry(v: i64) { set_persistent_expiry(v.max(0) as u64) }

/// Bind the key store's reporting and quota surface into `/proc` at boot,
/// before procfs registers its files. # C: O(1)
pub fn register_procfs_hooks() {
    procfs::hooks::keyring::set_report_hooks(keys_body, key_users_body);
    procfs::hooks::keyring::set_quota_hooks(
        (maxkeys, set_maxkeys), (maxbytes, set_maxbytes),
        (root_maxkeys, set_root_maxkeys), (root_maxbytes, set_root_maxbytes),
        (expiry, set_expiry));
}
