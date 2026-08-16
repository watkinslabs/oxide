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
//! That one store is the machine's `.fs-verity` keyring, and this module does
//! not hold a copy of it. It holds only the two accessors the keyring layer
//! installs at boot, so a certificate is trusted here exactly when the keyring
//! holds it — added, revoked, expired or restricted, the answer is the
//! keyring's. A trust set kept here as well would be a second place to look,
//! and the two could disagree the moment a key was revoked.
//!
//! The requirement knob is genuinely separate state, and stays here: it says
//! whether an ABSENT signature is tolerated, which is not a fact about any
//! key.

use core::sync::atomic::{AtomicBool, Ordering};

use pkey::pkcs7::TrustStore;
use sync::Spinlock;

struct VerityKeyLockClass;
impl sync::LockClass for VerityKeyLockClass {
    fn rank() -> u16 { 33 }
    fn name() -> &'static str { "VerityKeyLockClass" }
}

/// How the machine's trusted certificates are reached.
///
/// Two accessors rather than one because they answer different questions and
/// the cheap one is asked first: [`Source::links`] is "does this machine use
/// built-in signatures at all", which decides whether a signature blob is
/// parsed; [`Source::store`] is the trust set the chain is then checked
/// against.
#[derive(Copy, Clone)]
pub struct Source {
    /// Keys linked into the keyring, whatever state each is in.
    pub links: fn() -> usize,
    /// The certificates among them that can currently anchor a chain.
    pub store: fn() -> TrustStore,
}

/// Installed once at boot by the layer that owns the keyring. `None` before
/// that, which is the state a kernel that has not finished booting is in and
/// answers as an empty trust set.
static SOURCE: Spinlock<Option<Source>, VerityKeyLockClass> = Spinlock::new(None);

/// Bind the `.fs-verity` keyring in as the trust store.
///
/// Called from the crate that owns the keyring, because that crate depends on
/// this one and the dependency cannot be inverted. # C: O(1)
pub fn set_source(src: Source) { *SOURCE.lock() = Some(src); }

/// Read the installed accessors out and RELEASE the lock before either is
/// called: they take the key store's own lock, and calling into it while
/// holding this one would nest two subsystem locks for no reason. # C: O(1)
fn source() -> Option<Source> { *SOURCE.lock() }

/// Whether the keyring holds nothing.
///
/// A signed file is REFUSED against an empty keyring rather than accepted for
/// want of anything to check it against, and refused without the signature
/// being parsed at all — an unparsed blob is one less thing reachable by
/// anyone who can turn verity on.
/// # C: O(1)
pub fn is_empty() -> bool {
    match source() { Some(s) => (s.links)() == 0, None => true }
}

/// Run `f` against the trusted certificates.
///
/// The set is derived from the keyring on every call rather than cached, so a
/// certificate revoked between two verifications stops anchoring a chain at
/// the second one.
/// # C: O(members * len + f)
pub fn with_store<R>(f: impl FnOnce(&TrustStore) -> R) -> R {
    match source() {
        Some(s) => f(&(s.store)()),
        None => f(&TrustStore::new()),
    }
}

/// Whether an unsigned verity file is refused. # C: O(1)
pub fn require_signatures() -> bool { REQUIRE.load(Ordering::Relaxed) }

/// Set whether an unsigned verity file is refused. # C: O(1)
pub fn set_require_signatures(v: bool) { REQUIRE.store(v, Ordering::Relaxed); }

/// Whether every verity file must carry a valid built-in signature.
///
/// Independent of the store: a signature that is PRESENT is always checked,
/// whatever this says. This decides only whether an ABSENT one is tolerated.
static REQUIRE: AtomicBool = AtomicBool::new(false);

/// Detach the trust source and stop requiring signatures.
///
/// Exists for a test that has to start from a known keyring. Nothing in the
/// running system detaches it.
/// # C: O(1)
#[cfg(any(test, feature = "hosted"))]
pub fn reset_for_test() {
    *SOURCE.lock() = None;
    REQUIRE.store(false, Ordering::Relaxed);
}

/// A trust source backed by a fixed list of DER certificates, for a test that
/// needs one without a key store to hang it on. # C: O(1)
#[cfg(any(test, feature = "hosted"))]
pub fn set_test_source(links: fn() -> usize, store: fn() -> TrustStore) {
    set_source(Source { links, store });
}

/// Build a trust store from DER blobs, skipping any that does not parse.
/// # C: O(n * len)
#[cfg(any(test, feature = "hosted"))]
pub fn store_from_ders(ders: &[alloc::vec::Vec<u8>]) -> TrustStore {
    let mut s = TrustStore::new();
    for d in ders { let _ = s.add(d); }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Serialise against the other tests here: the state under test is
    /// process-wide, which is the property being asserted.
    static T: Spinlock<(), VerityKeyLockClass> = Spinlock::new(());

    /// One self-signed certificate, as a real DER blob.
    const CERT: &str = concat!(
        "308203373082021fa00302010202146d7991970d6881b5cef910b13e7045cab06bdd64300d06092a864886f70d01010b",
        "0500302b310e300c060355040a0c05526f6775653119301706035504030c10756e74727573746564207369676e657230",
        "1e170d3236303831363231343435325a170d3436303831313231343435325a302b310e300c060355040a0c05526f6775",
        "653119301706035504030c10756e74727573746564207369676e657230820122300d06092a864886f70d010101050003",
        "82010f003082010a0282010100a7dff4a4dd07c79aad57ba1c028214a98543ebb3ab35c14fa1037584098d8ef27c7644",
        "aee0528f76c4039a6a2a23ac0c363898dc0b19e6a7dee5a568bffb8c86e8bba4393129c627e351ebd23f468514464e14",
        "156a37d6e00a8d5c58721509dac21aad8121380150cebb1778442a180819169d6be91a0809931c4ad39ceb297913520b",
        "161feda77da1b1d2adc3cfdded6d2bff60e3f8024cfc210714eaa095c9884e28840b39633f5c83b2d4aade988a795301",
        "941d5072a20606c6b24b5deda5df844b6122f291fa78bd11cbbc14bae3296780e886e61f0966800017ddf0eae6a9fd42",
        "b81455e50bba720916942c918f3dcbff1e3085652918a03199bf6035630203010001a3533051301d0603551d0e041604",
        "14551c0599191626afac35229de8fbf7cab8d6d540301f0603551d23041830168014551c0599191626afac35229de8fb",
        "f7cab8d6d540300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038201010005352f30d3",
        "e08287027edbbb7fa875be6a625a802f314c26bfd1e410ca8c8a53cfd21e0c1f5f19342ff39e2619eadb0351b5af9e2c",
        "215e80cbad63ec1f82b0ea86f9afa460f64d5fda821b08762340237ccb8fdda95bb71c6d82f7d732fb399325534c4382",
        "d3dc7a728524e0ed143ac7168438202e56cb3505a52c06bb382dfaf36fbe25fc203a96e50059508a227da38b7a82f889",
        "5ab42fcd24da9519b730b7f9a2eeb99e98198a084dd666d86ab801406f19ba492a6e9f721b0ee4f05bc05bc39ef95c1c",
        "6651cd9348b17debe441edf9b610da89b1429e34b06fdf3481bdf35e3293f02e889424241fe2177635592883afca8b7c",
        "86a0b9697fa8c8411f6c46",
    );

    fn der() -> Vec<u8> {
        let b = CERT.as_bytes();
        let nyb = |c: u8| if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
        (0..b.len() / 2).map(|i| nyb(b[i * 2]) << 4 | nyb(b[i * 2 + 1])).collect()
    }

    fn one_link() -> usize { 1 }
    fn one_cert() -> TrustStore { store_from_ders(&[der()]) }
    fn no_usable_cert() -> TrustStore { TrustStore::new() }

    #[test]
    fn with_no_source_installed_nothing_is_trusted() {
        let _g = T.lock();
        reset_for_test();
        assert!(is_empty(), "a kernel with no keyring bound trusts something");
        assert!(!require_signatures(), "a fresh machine refuses unsigned files");
        with_store(|s| assert!(s.is_empty()));
    }

    #[test]
    fn the_trusted_set_is_whatever_the_source_reports() {
        let _g = T.lock();
        reset_for_test();
        set_test_source(one_link, one_cert);
        assert!(!is_empty());
        with_store(|s| assert_eq!(s.len(), 1, "the source's certificate did not reach the verifier"));
        reset_for_test();
    }

    /// A link whose key can no longer anchor a chain — revoked, expired, or
    /// not a certificate at all — still counts as a link. The machine uses
    /// built-in signatures, so the blob IS parsed and the signature then fails
    /// on its merits rather than being skipped.
    #[test]
    fn a_link_that_anchors_nothing_still_means_signatures_are_in_use() {
        let _g = T.lock();
        reset_for_test();
        set_test_source(one_link, no_usable_cert);
        assert!(!is_empty(), "a populated keyring reported as unused");
        with_store(|s| assert!(s.is_empty(), "an unusable key anchored a chain"));
        reset_for_test();
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
}
