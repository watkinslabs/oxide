// The `.fs-verity` keyring: the certificates an fs-verity built-in signature
// must chain to, and the ONLY way one gets there.
//
// There is no private door into this trust store. A certificate becomes
// trusted exactly one way — `add_key(2)`/`KEYCTL_LINK` puts an `asymmetric`
// key into this keyring — so the permission model, the quota, `/proc/keys`,
// `KEYCTL_RESTRICT_KEYRING` and the revocation state all apply to verity trust
// automatically, and nothing can trust a certificate the keyring does not
// hold. The userspace operation is `keyctl padd asymmetric '' %keyring:.fs-verity`.
//
// The verifier lives below this crate, so the direction has to be an install
// rather than a call: [`init`] hands `vfs::verity_keys` the two accessors that
// read THIS keyring, which is why the file checker and `keyctl(2)` can never
// disagree about which certificates are trusted.

use core::sync::atomic::{AtomicI32, Ordering};

use pkey::pkcs7::TrustStore;

use super::perm::key_validate;
use super::store::{KeyNs, Store, TaskIds, STORE};
use super::types;
use super::uapi::*;

/// Serial of the machine's `.fs-verity` keyring. Zero until [`init`] runs,
/// which is the state a kernel that has not reached that point in boot is in
/// — and the reason every reader below answers "nothing is trusted" rather
/// than faulting.
static RING: AtomicI32 = AtomicI32::new(0);

/// Create the keyring and make it the trust store the verity verifier reads.
///
/// Idempotent: a second call finds the keyring already minted and reinstalls
/// the same accessors. # C: O(log N)
pub fn init() {
    let serial = {
        let mut g = STORE.lock();
        let s = match existing(&g) {
            Some(s) => s,
            // `KEY_ALLOC_NOT_IN_QUOTA`: a machine-wide keyring is not charged
            // to root's key quota, so an administrator cannot lock themselves
            // out of verity trust by filling that quota elsewhere.
            None => {
                let ns = KeyNs::of(&TaskIds::default(), types::keyring_type());
                g.mint_not_in_quota(types::keyring_type(), FS_VERITY_KEYRING_NAME,
                    ROOT_UID, ROOT_GID, FS_VERITY_KEYRING_PERM, ns)
                    .expect("the fs-verity keyring is allocated outside every quota and cannot be refused")
            }
        };
        // The kernel's own reference. Nothing links this keyring, so without it
        // the collector reaps the machine's verity trust store.
        g.keys.get_mut(&s).expect("just minted or just found under the held lock").kernel_held = true;
        s
    };
    RING.store(serial, Ordering::Release);
    vfs::verity_keys::set_source(vfs::verity_keys::Source { links, store });
}

/// uid/gid the keyring is owned by. Ownership is what the USER permission byte
/// is tested against, so these two values ARE the "only root may modify it"
/// rule.
const ROOT_UID: u32 = 0;
const ROOT_GID: u32 = 0;

/// The keyring's serial, or `None` before boot created it. # C: O(1)
pub fn keyring_serial() -> Option<i32> {
    match RING.load(Ordering::Acquire) { 0 => None, s => Some(s) }
}

/// A keyring already minted under this description, so [`init`] does not mint
/// a second one. # C: O(N)
fn existing(g: &Store) -> Option<i32> {
    g.keys.values()
        .find(|k| k.is_keyring() && k.description == FS_VERITY_KEYRING_NAME && !k.invalidated)
        .map(|k| k.serial)
}

/// How many keys are linked here, whatever state each is in — the count the
/// verifier tests to decide whether a signed file is refused without the
/// PKCS#7 blob being parsed at all.
///
/// Deliberately NOT the number of usable certificates. The point of the test
/// is to keep the message parser unreachable on a machine that does not use
/// built-in signatures; once an administrator has linked anything at all, the
/// machine does use them, and a signature that then fails to verify is an
/// authentication answer rather than a reason to skip the check.
/// # C: O(log N)
fn links() -> usize {
    let Some(ring) = keyring_serial() else { return 0; };
    let g = STORE.lock();
    g.keys.get(&ring).map(|k| k.members.len()).unwrap_or(0)
}

/// The trusted certificates, built from the keyring's live membership.
///
/// A member is skipped when it is not an `asymmetric` key, when it is revoked
/// / invalidated / past its expiry, or when its payload is a private key
/// rather than a certificate — a chain can only be anchored by a certificate,
/// and a key whose owner revoked it must stop anchoring one immediately.
/// # C: O(members * len)
fn store() -> TrustStore {
    let mut out = TrustStore::new();
    let Some(ring) = keyring_serial() else { return out; };
    let now_ns = super::monotonic_now_ns();
    let g = STORE.lock();
    let Some(members) = g.keys.get(&ring).map(|k| k.members.clone()) else { return out; };
    for s in members {
        let Some(k) = g.keys.get(&s) else { continue; };
        if k.key_type.name != ASYMMETRIC_KEY_TYPE { continue; }
        if k.read_state() != KEY_IS_POSITIVE { continue; }
        if key_validate(k, now_ns).is_err() { continue; }
        // A blob that is not an X.509 certificate anchors nothing; `add_key`
        // admitted it because the asymmetric type also parses private keys.
        if out.add(&k.payload).is_err() { continue; }
    }
    out
}

/// Every certificate the keyring currently anchors, for a caller that wants
/// the DER rather than a built store. # C: O(members * len)
#[cfg(test)]
pub fn certificates() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let Some(ring) = keyring_serial() else { return alloc::vec::Vec::new(); };
    let g = STORE.lock();
    let Some(members) = g.keys.get(&ring).map(|k| k.members.clone()) else { return alloc::vec::Vec::new(); };
    members.iter().filter_map(|s| g.keys.get(s))
        .filter(|k| k.key_type.name == ASYMMETRIC_KEY_TYPE)
        .map(|k| k.payload.clone()).collect()
}
