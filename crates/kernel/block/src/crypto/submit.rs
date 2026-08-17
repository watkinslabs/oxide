//! The choke point every request carrying an encryption context goes through.
//!
//! There is exactly one of these on purpose. A submitter that reached a driver
//! directly with a context attached would hand the device a request it may not
//! understand: the device would write the plaintext it was given and report
//! success, and nothing downstream can tell that apart from a device that
//! encrypted. So the decision — this device can serve this context, or the
//! fallback must — is made here, once, and there is no path that reaches a
//! driver with a context still unserved.
//!
//! The order of the checks mirrors what each one can still recover from. A
//! context on an operation that carries no data is a caller error and is
//! refused. A context the device serves natively is passed straight down. A
//! context it cannot serve goes to the fallback, which either does the crypto
//! or refuses — it never passes the request down unencrypted.

extern crate alloc;
use alloc::sync::Arc;

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::crypto::fallback;
use crate::crypto::key::{Config, Key, KeyType, SW_SECRET_SIZE};
use crate::crypto::profile::Profile;
use crate::types::{BlockError, BlockOp, KResult};

/// Whether `dev` itself can serve `cfg`, with no software help. # C: O(1)
pub fn config_supported_natively(dev: &dyn BlockDevice, cfg: &Config) -> bool {
    profile_supports(dev.crypto_profile(), cfg)
}

/// The same, asked of a profile directly.
///
/// A caller that holds the profile rather than the device — a filesystem
/// deciding at key-setup time which layer will encrypt a file — asks here, so
/// the two askers cannot drift into different answers.
/// # C: O(1)
pub fn profile_supports(profile: Option<&Profile>, cfg: &Config) -> bool {
    profile.is_some_and(|p| p.supports(cfg))
}

/// Whether `cfg` can be served on `dev` at all, by the device or by software.
///
/// A raw key is always servable, because the fallback exists. A wrapped key is
/// servable only by hardware that takes wrapped keys, because there is nothing
/// software can do with a blob it cannot unwrap.
/// # C: O(1)
pub fn config_supported(dev: &dyn BlockDevice, cfg: &Config) -> bool {
    cfg.key_type == KeyType::Raw || config_supported_natively(dev, cfg)
}

/// Prepare to use `key` on `dev`, or say why it cannot be used.
///
/// Called away from the I/O path, and required before any request carrying the
/// key: it is the point at which "this key cannot be used here" is still an
/// answer the caller can act on. Discovering it during a write leaves only
/// wrong bytes or a lost write.
/// # C: O(1)
pub fn start_using_key(dev: &dyn BlockDevice, key: &Arc<Key>) -> KResult<()> {
    start_using_key_on(dev.crypto_profile(), key)
}

/// The same, against the profile the key will be used under.
///
/// Every path that prepares a key must come through one of these two. Skipping
/// it leaves the software fallback without the construction it would need, and
/// the first write is where that is discovered — which is the one place it
/// must never be.
/// # C: O(1)
pub fn start_using_key_on(profile: Option<&Profile>, key: &Arc<Key>) -> KResult<()> {
    let cfg = key.config();
    if profile_supports(profile, cfg) { return Ok(()); }
    // No software fallback can serve a key software cannot read.
    if cfg.key_type != KeyType::Raw { return Err(BlockError::Eopnotsupp); }
    fallback::start_using_mode(cfg.mode)
}

/// Take `key` out of `dev` — out of its keyslots if it serves the key itself,
/// out of the fallback's otherwise.
///
/// Must be called before the key is dropped, for every device it was used on.
/// # C: O(keyslots)
pub fn evict_key(dev: &dyn BlockDevice, key: &Arc<Key>) -> KResult<()> {
    if config_supported_natively(dev, key.config()) {
        return dev.crypto_profile().ok_or(BlockError::Einval)?.evict_key(key);
    }
    fallback::evict_key(key)
}

/// Ask `dev` to derive the software secret from an ephemerally-wrapped key.
///
/// Refused on a device with no inline encryption and on one that takes only
/// raw keys: the secret is a hardware derivation, and there is no software
/// stand-in that would be the same secret.
/// # C: one hardware operation
pub fn derive_sw_secret(dev: &dyn BlockDevice, eph_key: &[u8])
    -> KResult<[u8; SW_SECRET_SIZE]> {
    dev.crypto_profile().ok_or(BlockError::Eopnotsupp)?.derive_sw_secret(eph_key)
}

/// Submit `req`, serving its encryption context if it has one.
///
/// A request with no context is submitted unchanged, which is every request
/// on an unencrypted filesystem and the reason this may be the only submission
/// path a caller uses.
/// # C: O(len(buffer)) when the fallback runs, else the driver's cost
pub fn submit_sync(dev: &dyn BlockDevice, req: &mut BlockRequest) -> KResult<()> {
    let Some(ctx) = req.crypt.clone() else { return dev.submit_sync(req) };
    // An operation with no payload has nothing to encrypt, so a context on one
    // is a caller that attached it to the wrong request. Serving it would mean
    // deciding what a zero-length encryption means; refusing says so.
    if !matches!(req.op, BlockOp::Read | BlockOp::Write) { return Err(BlockError::Einval); }
    if config_supported_natively(dev, ctx.key().config()) {
        // The device does the crypto in line with the transfer. It needs the
        // key resident in one of its slots for the whole transfer, which is
        // what holding the reference across the submit guarantees.
        let profile = dev.crypto_profile().ok_or(BlockError::Einval)?;
        let _slot = profile.get_keyslot(ctx.key())?;
        return dev.submit_sync(req);
    }
    match req.op {
        BlockOp::Write => {
            // The caller's buffer is left holding PLAINTEXT, exactly as it was
            // handed over: the ciphertext lives in a copy for the duration of
            // the transfer and nothing else. A caller whose buffer came back
            // enciphered would write it a second time on a retry and encrypt
            // it twice.
            let plain = core::mem::take(&mut req.buffer);
            let mut ct = plain.clone();
            let enc = fallback::encrypt(&ctx, &mut ct);
            if enc.is_err() { req.buffer = plain; return enc; }
            req.buffer = ct;
            let r = dev.submit_sync(req);
            req.buffer = plain;
            r
        }
        BlockOp::Read => {
            dev.submit_sync(req)?;
            fallback::decrypt(&ctx, &mut req.buffer)
        }
        _ => Err(BlockError::Einval),
    }
}
