// The `/proc/sys/kernel/keys/` live values.
//
// These are variables, not constants, because every one of them is a sysctl an
// administrator writes at runtime and the key paths re-read on every
// allocation. A constant here plus a procfs-side cell would be two numbers that
// disagree the moment anyone writes one — the ceiling would read back changed
// and `add_key(2)` would keep enforcing the old one.

use core::sync::atomic::{AtomicU64, Ordering};

use super::super::uapi::*;

/// The four per-uid ceilings, in the order [`QuotaKnob`] indexes them.
static QUOTA_LIMITS: [AtomicU64; 4] = [
    AtomicU64::new(KEY_QUOTA_MAXKEYS),
    AtomicU64::new(KEY_QUOTA_MAXBYTES),
    AtomicU64::new(KEY_QUOTA_ROOT_MAXKEYS),
    AtomicU64::new(KEY_QUOTA_ROOT_MAXBYTES),
];

/// `persistent_keyring_expiry`, the window `KEYCTL_GET_PERSISTENT` refreshes.
static PERSISTENT_EXPIRY: AtomicU64 = AtomicU64::new(PERSISTENT_KEYRING_EXPIRY);

/// The `/proc/sys/kernel/keys/` quota knobs backing [`QUOTA_LIMITS`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum QuotaKnob { MaxKeys = 0, MaxBytes = 1, RootMaxKeys = 2, RootMaxBytes = 3 }

/// Read a quota ceiling. # C: O(1)
pub fn quota_limit(k: QuotaKnob) -> u64 { QUOTA_LIMITS[k as usize].load(Ordering::Relaxed) }

/// Write a quota ceiling — the sysctl store path. Lowering one below what a uid
/// already holds reclaims nothing: the charge is only re-tested on the next
/// allocation, as Linux's is. # C: O(1)
pub fn set_quota_limit(k: QuotaKnob, v: u64) { QUOTA_LIMITS[k as usize].store(v, Ordering::Relaxed); }

/// Seconds a persistent keyring survives without use. # C: O(1)
pub fn persistent_expiry() -> u64 { PERSISTENT_EXPIRY.load(Ordering::Relaxed) }

/// Write it. Unlike the quota ceilings this one accepts 0, which makes every
/// persistent keyring expire the moment it is handed out — the way an
/// administrator turns the facility off without a config option. # C: O(1)
pub fn set_persistent_expiry(v: u64) { PERSISTENT_EXPIRY.store(v, Ordering::Relaxed); }

/// A uid's key-count ceiling — `key_quota_root_maxkeys` for root, else
/// `key_quota_maxkeys`. # C: O(1)
pub fn max_keys(uid: u32) -> u64 {
    quota_limit(if uid == ROOT_UID { QuotaKnob::RootMaxKeys } else { QuotaKnob::MaxKeys })
}

/// A uid's key-byte ceiling — `key_quota_root_maxbytes` / `key_quota_maxbytes`.
/// # C: O(1)
pub fn max_bytes(uid: u32) -> u64 {
    quota_limit(if uid == ROOT_UID { QuotaKnob::RootMaxBytes } else { QuotaKnob::MaxBytes })
}
