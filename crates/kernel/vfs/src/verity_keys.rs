//! The certificates a verity signature's chain must reach, and whether an
//! unsigned verity file may be read at all.
//!
//! ONE store for the whole system, not one per mount. The hash tree makes a
//! file's bytes self-consistent; it says nothing about who chose the root, and
//! a built-in signature is what ties that root to a key. Which keys are
//! trusted is a property of the MACHINE — the administrator decides it once —
//! so a per-mount copy would let two mounts of the same medium disagree about
//! whether the same file is authentic, and would leave a certificate added
//! after a mount applying to some filesystems and not others.
//!
//! This lives here rather than in the crate that owns the certificate parsing
//! for two reasons. It is filesystem-independent policy, which is what this
//! layer is for; and the parsing crate states that nothing in it reads a
//! clock, a keyring or a random pool, so that every path through it is
//! reproducible under test. A mutable keyring there would break an invariant
//! its own callers rely on.
//!
//! Readers take the store by reference under the lock rather than copying it:
//! a snapshot is a second copy of the trust state, and the whole point of one
//! store is that there is no second copy to go stale.

use core::sync::atomic::{AtomicBool, Ordering};

use pkey::pkcs7::TrustStore;
use sync::Spinlock;

struct VerityKeyLockClass;
impl sync::LockClass for VerityKeyLockClass {
    fn rank() -> u16 { 33 }
    fn name() -> &'static str { "VerityKeyLockClass" }
}

/// The trusted certificates. Empty until something adds one, which is the
/// state a kernel that supports built-in signatures but does not use them
/// runs in.
static KEYS: Spinlock<Option<TrustStore>, VerityKeyLockClass> = Spinlock::new(None);

/// Whether every verity file must carry a valid built-in signature.
///
/// Independent of the store: a signature that is PRESENT is always checked,
/// whatever this says. This decides only whether an ABSENT one is tolerated.
static REQUIRE: AtomicBool = AtomicBool::new(false);

/// Trust one DER certificate for verity signatures.
///
/// Errors when the blob does not parse. Adding is the only way in and there
/// is deliberately no way to remove one individually: a chain that verified a
/// file's measurement once must go on verifying it, and the reference's own
/// keyring is add-only for the same reason.
/// # C: O(len)
pub fn add_cert(der: &[u8]) -> Result<(), ()> {
    let mut g = KEYS.lock();
    let store = g.get_or_insert_with(TrustStore::new);
    store.add(der).map_err(|_| ())
}

/// Whether the keyring holds nothing.
///
/// A signed file is REFUSED against an empty keyring rather than accepted for
/// want of anything to check it against, and refused without the signature
/// being parsed at all — an unparsed blob is one less thing reachable by
/// anyone who can turn verity on.
/// # C: O(1)
pub fn is_empty() -> bool {
    KEYS.lock().as_ref().is_none_or(TrustStore::is_empty)
}

/// Run `f` against the trusted certificates.
///
/// By reference and under the lock, so no caller ends up holding a copy of
/// the trust state that a later addition does not reach.
/// # C: O(f)
pub fn with_store<R>(f: impl FnOnce(&TrustStore) -> R) -> R {
    let g = KEYS.lock();
    match g.as_ref() {
        Some(s) => f(s),
        None => f(&TrustStore::new()),
    }
}

/// Whether an unsigned verity file is refused. # C: O(1)
pub fn require_signatures() -> bool { REQUIRE.load(Ordering::Relaxed) }

/// Set whether an unsigned verity file is refused. # C: O(1)
pub fn set_require_signatures(v: bool) { REQUIRE.store(v, Ordering::Relaxed); }

/// Forget every trusted certificate and stop requiring signatures.
///
/// Exists for a test that has to start from a known keyring. Nothing in the
/// running system removes a certificate; see [`add_cert`].
/// # C: O(1)
#[cfg(any(test, feature = "hosted"))]
pub fn reset_for_test() {
    *KEYS.lock() = None;
    REQUIRE.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialise against the other tests here: the state under test is
    /// process-wide, which is the property being asserted.
    static T: Spinlock<(), VerityKeyLockClass> = Spinlock::new(());

    #[test]
    fn an_empty_keyring_is_empty_and_demands_nothing() {
        let _g = T.lock();
        reset_for_test();
        assert!(is_empty(), "a fresh keyring holds something");
        assert!(!require_signatures(), "a fresh machine refuses unsigned files");
        with_store(|s| assert!(s.is_empty()));
    }

    #[test]
    fn the_knob_is_one_value_for_the_whole_machine() {
        let _g = T.lock();
        reset_for_test();
        set_require_signatures(true);
        assert!(require_signatures());
        set_require_signatures(false);
        assert!(!require_signatures());
        reset_for_test();
    }

    #[test]
    fn a_blob_that_is_not_a_certificate_does_not_join_the_keyring() {
        let _g = T.lock();
        reset_for_test();
        assert!(add_cert(b"not a certificate").is_err());
        assert!(is_empty(), "a refused blob was added anyway");
        reset_for_test();
    }
}
