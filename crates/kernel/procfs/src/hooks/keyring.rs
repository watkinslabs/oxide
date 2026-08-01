// The key store's reporting + quota surface, which procfs RENDERS but does not
// own. procfs is a leaf crate and the crate holding the key store depends on
// it, so the binding is a boot-installed accessor rather than a procfs-side
// copy of the state: a copy would let `/proc/keys` and `/proc/sys/kernel/keys/*`
// report a key set and a ceiling that no `keyctl(2)` mutation and no key
// allocation ever consult.

use core::sync::atomic::{AtomicPtr, Ordering};
use alloc::vec::Vec;

/// What an unbound ceiling reports: no key store has installed itself, so
/// nothing can be charged against any ceiling at all. A plausible-looking
/// Linux default here would be a second copy of the boot value with nothing
/// enforcing it.
const UNBOUND: i64 = 0;

/// `proc_dointvec_minmax` window every `/proc/sys/kernel/keys/` ceiling is
/// registered with: `extra1 = 1`, `extra2 = INT_MAX`. A zero ceiling is out of
/// range — a uid that may hold no key at all is not an expressible quota.
pub const KEY_QUOTA_BOUNDS: (i64, i64) = (1, i32::MAX as i64);

/// `persistent_keyring_expiry`'s window starts at ZERO, not one: setting it to
/// 0 expires every persistent keyring as it is handed out, which is how the
/// facility is turned off without a rebuild.
pub const KEY_EXPIRY_BOUNDS: (i64, i64) = (0, i32::MAX as i64);

static KEYS:      AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static KEY_USERS: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// One `/proc/sys/kernel/keys/` ceiling's live accessor pair. Four named slots
/// rather than one index-keyed table: an integer knob index crossing the crate
/// boundary is a number both sides must agree on with nothing to check it.
struct QuotaSlot { get: AtomicPtr<()>, set: AtomicPtr<()> }

impl QuotaSlot {
    const fn new() -> Self {
        QuotaSlot { get: AtomicPtr::new(core::ptr::null_mut()), set: AtomicPtr::new(core::ptr::null_mut()) }
    }
    fn install(&self, get: fn() -> i64, set: fn(i64)) {
        self.get.store(get as *mut (), Ordering::Release);
        self.set.store(set as *mut (), Ordering::Release);
    }
    fn read(&self) -> i64 {
        let p = self.get.load(Ordering::Acquire);
        if p.is_null() { return UNBOUND; }
        // SAFETY: pointer was set from a `fn() -> i64` by QuotaSlot::install.
        let f: fn() -> i64 = unsafe { core::mem::transmute(p) }; f()
    }
    fn write(&self, v: i64) {
        let p = self.set.load(Ordering::Acquire);
        if p.is_null() { return; }
        // SAFETY: pointer was set from a `fn(i64)` by QuotaSlot::install.
        let f: fn(i64) = unsafe { core::mem::transmute(p) }; f(v)
    }
}

static MAXKEYS:       QuotaSlot = QuotaSlot::new();
static MAXBYTES:      QuotaSlot = QuotaSlot::new();
static ROOT_MAXKEYS:  QuotaSlot = QuotaSlot::new();
static ROOT_MAXBYTES: QuotaSlot = QuotaSlot::new();
static PERSISTENT_EXPIRY: QuotaSlot = QuotaSlot::new();

/// Bind `/proc/keys` and `/proc/key-users` to the store's renderers. Both are
/// per-read: `/proc/keys` is filtered by the READING task's view permission, so
/// a body captured once and shared would hand every reader the first reader's
/// key set. # C: O(1)
pub fn set_report_hooks(keys: fn() -> Vec<u8>, key_users: fn() -> Vec<u8>) {
    KEYS.store(keys as *mut (), Ordering::Release);
    KEY_USERS.store(key_users as *mut (), Ordering::Release);
}

/// Bind the `/proc/sys/kernel/keys/` values to the live variables the
/// key allocation path tests. # C: O(1)
pub fn set_quota_hooks(
    maxkeys: (fn() -> i64, fn(i64)),
    maxbytes: (fn() -> i64, fn(i64)),
    root_maxkeys: (fn() -> i64, fn(i64)),
    root_maxbytes: (fn() -> i64, fn(i64)),
    persistent_expiry: (fn() -> i64, fn(i64)),
) {
    MAXKEYS.install(maxkeys.0, maxkeys.1);
    MAXBYTES.install(maxbytes.0, maxbytes.1);
    ROOT_MAXKEYS.install(root_maxkeys.0, root_maxkeys.1);
    ROOT_MAXBYTES.install(root_maxbytes.0, root_maxbytes.1);
    PERSISTENT_EXPIRY.install(persistent_expiry.0, persistent_expiry.1);
}

/// `/proc/keys` body for the CURRENT reader. Empty while no store is bound —
/// there are then no keys to list, which is what an empty file says. # C: O(N)
pub fn keys() -> Vec<u8> {
    let p = KEYS.load(Ordering::Acquire);
    if p.is_null() { return Vec::new(); }
    // SAFETY: pointer was set from a `fn() -> Vec<u8>` via set_report_hooks.
    let f: fn() -> Vec<u8> = unsafe { core::mem::transmute(p) }; f()
}

/// `/proc/key-users` body — the per-uid charge table. # C: O(N)
pub fn key_users() -> Vec<u8> {
    let p = KEY_USERS.load(Ordering::Acquire);
    if p.is_null() { return Vec::new(); }
    // SAFETY: pointer was set from a `fn() -> Vec<u8>` via set_report_hooks.
    let f: fn() -> Vec<u8> = unsafe { core::mem::transmute(p) }; f()
}

/// `kernel.keys.maxkeys`. # C: O(1)
pub fn maxkeys() -> i64 { MAXKEYS.read() }
/// # C: O(1)
pub fn set_maxkeys(v: i64) { MAXKEYS.write(v) }
/// `kernel.keys.maxbytes`. # C: O(1)
pub fn maxbytes() -> i64 { MAXBYTES.read() }
/// # C: O(1)
pub fn set_maxbytes(v: i64) { MAXBYTES.write(v) }
/// `kernel.keys.root_maxkeys`. # C: O(1)
pub fn root_maxkeys() -> i64 { ROOT_MAXKEYS.read() }
/// # C: O(1)
pub fn set_root_maxkeys(v: i64) { ROOT_MAXKEYS.write(v) }
/// `kernel.keys.root_maxbytes`. # C: O(1)
pub fn root_maxbytes() -> i64 { ROOT_MAXBYTES.read() }
/// # C: O(1)
pub fn set_root_maxbytes(v: i64) { ROOT_MAXBYTES.write(v) }
/// `kernel.keys.persistent_keyring_expiry` — the window every successful
/// `KEYCTL_GET_PERSISTENT` refreshes. # C: O(1)
pub fn persistent_expiry() -> i64 { PERSISTENT_EXPIRY.read() }
/// # C: O(1)
pub fn set_persistent_expiry(v: i64) { PERSISTENT_EXPIRY.write(v) }
