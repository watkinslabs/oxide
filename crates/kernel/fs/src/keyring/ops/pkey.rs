// `KEYCTL_PKEY_*` cores: the information string every one of them takes, the
// key they all read, the length rules each command applies, and the mapping
// from a public-key failure to the errno userspace sees.
//
// The calculations themselves are `pkey`; what lives here is the keyring's
// half — which key may be used, under what encoding, with what widths.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ::pkey::{AsymmetricKey, KeyQuery, Operation, PkeyError};
use syscall::errno::Errno;

use super::super::perm;
use super::super::store::STORE;
use super::super::uapi::*;
use super::{e, Ctx};

/// This module IS the public-key capability: the reported
/// `KEYCTL_CAPS0_PUBLIC_KEY` bit is read from here, so the bit and the
/// commands cannot disagree.
pub const SUPPORTED: bool = true;

/// The parsed `enc=`/`hash=` information string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub encoding: String,
    pub hash: Option<String>,
}

impl Default for Info {
    /// No `enc=` means the caller is supplying raw values. # C: O(1)
    fn default() -> Self { Self { encoding: PKEY_ENCODING_DEFAULT.to_string(), hash: None } }
}

/// Parse the supplementary information string: space- or tab-separated
/// `key=value` pairs, of which exactly two keys are defined.
///
/// Each rule refuses a request that could otherwise be read two ways:
///   * an unknown key is EINVAL, not ignored — a caller asking for a
///     parameter this kernel does not implement must not get a silently
///     different operation;
///   * a repeated key is EINVAL rather than last-one-wins;
///   * an empty value is EINVAL.
/// # C: O(len)
pub fn parse_info(info: &str) -> Result<Info, Errno> {
    let mut out = Info::default();
    let (mut saw_enc, mut saw_hash) = (false, false);
    for tok in info.split([' ', '\t']) {
        if tok.is_empty() { continue; }
        let (k, v) = tok.split_once('=').ok_or(Errno::Einval)?;
        if v.is_empty() { return Err(Errno::Einval); }
        match k {
            PKEY_INFO_ENC => {
                if saw_enc { return Err(Errno::Einval); }
                saw_enc = true;
                out.encoding = v.to_string();
            }
            PKEY_INFO_HASH => {
                if saw_hash { return Err(Errno::Einval); }
                saw_hash = true;
                out.hash = Some(v.to_string());
            }
            _ => return Err(Errno::Einval),
        }
    }
    Ok(out)
}

/// Read the key the operation names.
///
/// The permission required is SEARCH, not READ: a public-key operation does
/// not hand the key material back, so a key that may be found may be used.
/// A key of any other type is EOPNOTSUPP — it exists, it simply has no
/// asymmetric operations. # C: O(log N + payload)
pub fn load_key(c: &Ctx, serial: i32) -> Result<AsymmetricKey, i64> {
    let mut g = STORE.lock();
    let real = g.resolve(serial, &c.t).map_err(e)?;
    perm::check_perm(&g, real, &c.t, KEY_NEED_SEARCH, perm::Lookup::Full, c.now_ns)?;
    let k = g.keys.get(&real).expect("the permission check proved existence under the same held lock");
    if k.key_type.name != ASYMMETRIC_KEY_TYPE { return Err(e(Errno::Eopnotsupp)); }
    // The payload is the blob as it was added; it parsed once at add time, so
    // a failure here would mean the stored bytes changed underneath us.
    AsymmetricKey::parse(&k.payload).map_err(|err| e(errno_for(err)))
}

/// `KEYCTL_PKEY_QUERY` core. # C: O(log N + parse)
pub fn query_core(c: &Ctx, serial: i32, info: &Info) -> Result<KeyQuery, i64> {
    let key = load_key(c, serial)?;
    key.query(&info.encoding, info.hash.as_deref()).map_err(|err| e(errno_for(err)))
}

/// The length rules `KEYCTL_PKEY_ENCRYPT` / `_DECRYPT` / `_SIGN` / `_VERIFY`
/// apply to the caller's declared sizes, before any calculation runs.
///
/// Each operation is bounded by the widths the QUERY reports: an input longer
/// than the operation's input ceiling, or an output buffer wider than its
/// output ceiling, is EINVAL. Returns the number of bytes the operation
/// produces, which is what the caller's output buffer must be able to take.
/// # C: O(1)
pub fn vet_lengths(op: Operation, q: &KeyQuery, in_len: u64, out_len: u64) -> Result<u64, Errno> {
    let (in_max, out_max) = match op {
        Operation::Encrypt => (q.max_dec_size, q.max_enc_size),
        Operation::Decrypt => (q.max_enc_size, q.max_dec_size),
        Operation::Sign    => (q.max_data_size, q.max_sig_size),
        Operation::Verify  => (q.max_data_size, q.max_sig_size),
    };
    if in_len > in_max as u64 || out_len > out_max as u64 { return Err(Errno::Einval); }
    Ok(out_max as u64)
}

/// `KEYCTL_PKEY_ENCRYPT` / `_DECRYPT` / `_SIGN` core. `rand` supplies
/// encryption padding. # C: O(rsa)
pub fn eds_core<R: FnMut(&mut [u8])>(key: &AsymmetricKey, op: Operation, info: &Info,
    input: &[u8], rand: R) -> Result<Vec<u8>, i64>
{
    key.eds(op, &info.encoding, info.hash.as_deref(), input, rand)
        .map_err(|err| e(errno_for(err)))
}

/// `KEYCTL_PKEY_VERIFY` core: 0 when the signature is this key's over this
/// digest. # C: O(rsa)
pub fn verify_core(key: &AsymmetricKey, info: &Info, digest: &[u8], sig: &[u8]) -> Result<(), i64> {
    key.verify(&info.encoding, info.hash.as_deref(), digest, sig)
        .map_err(|err| e(errno_for(err)))
}

/// The errno each public-key failure surfaces as.
///
/// The distinctions matter to a caller: a signature that verified as
/// well-formed but did not match is a REJECTED key, which is an authentication
/// result, while a block that was not a signature at all is a bad message,
/// which is a protocol result. Collapsing them would leave userspace unable to
/// tell an attack from a bug. # C: O(1)
pub fn errno_for(err: PkeyError) -> Errno {
    match err {
        PkeyError::BadMessage => Errno::Ebadmsg,
        PkeyError::Rejected => Errno::Ekeyrejected,
        PkeyError::Overflow => Errno::Eoverflow,
        PkeyError::NoPackage => Errno::Enopkg,
        PkeyError::NoAlgorithm => Errno::Enoent,
        PkeyError::Unsupported => Errno::Eopnotsupp,
        // A key that cannot perform the operation because it holds only the
        // public half fails the same way a malformed request does: the
        // arithmetic has no private exponent to use.
        PkeyError::BadKey | PkeyError::Invalid | PkeyError::NoPrivateKey => Errno::Einval,
    }
}
