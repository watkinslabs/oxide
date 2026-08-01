// `KEYCTL_DH_COMPUTE` core: the three key payloads it reads, the parameter
// admission rules, the modular exponentiation itself, and the counter-mode
// key-derivation variant.
//
// Every decision this command makes lives here, so the syscall entry stays a
// copy-in / call / copy-out shim and the hosted tests can drive the whole
// operation for an arbitrary caller without user memory.

use alloc::vec::Vec;

use crypt::Digest;
use mpi::Mpi;
use syscall::errno::Errno;

use super::super::perm;
use super::super::store::STORE;
use super::super::uapi::*;
use super::{e, Ctx};

/// This module IS the Diffie-Hellman capability: the reported
/// `KEYCTL_CAPS0_DIFFIE_HELLMAN` bit is read from here rather than from a list
/// kept next to the dispatch, so the bit and the command cannot disagree.
pub const SUPPORTED: bool = true;

/// Read one Diffie-Hellman input from a key.
///
/// Three separate outcomes, none of them interchangeable:
///   * every lookup failure — no such serial, no permission, an id out of
///     range — collapses to ENOKEY, so this command never reports WHY a key
///     it was pointed at is unusable;
///   * a key whose type is not `user` is EOPNOTSUPP: the payload of a `logon`
///     key is write-only and a keyring has none, so neither can supply a
///     number;
///   * a key that is revoked, invalidated or expired reports that state
///     directly, because it passed the lookup and only then failed validation.
/// # C: O(log N + payload)
pub fn dh_data_from_key(c: &Ctx, serial: i32) -> Result<Vec<u8>, i64> {
    let mut g = STORE.lock();
    let real = match g.resolve(serial, &c.t) { Ok(s) => s, Err(_) => return Err(e(Errno::Enokey)) };
    if perm::check_perm(&g, real, &c.t, KEY_NEED_READ, perm::Lookup::Full, c.now_ns).is_err() {
        return Err(e(Errno::Enokey));
    }
    let k = g.keys.get(&real).expect("the permission check proved existence under the same held lock");
    if k.key_type.name != USER_KEY_TYPE { return Err(e(Errno::Eopnotsupp)); }
    Ok(k.payload.clone())
}

/// Admission rules on the three raw byte strings, applied before any
/// arithmetic:
///   * the private value and the base may not be WIDER than the modulus;
///   * a modulus of zero is refused — it is not a prime, and reduction modulo
///     zero is undefined;
///   * the modulus must be at least 1536 bits as supplied, counted on the raw
///     payload width rather than on the value, so a caller cannot pass a short
///     modulus zero-padded out to a respectable length;
///   * no input may exceed the import ceiling on a multi-precision integer.
/// # C: O(len)
pub fn vet_inputs(p: &[u8], g: &[u8], x: &[u8]) -> Result<(), Errno> {
    if x.len() > p.len() || g.len() > p.len() { return Err(Errno::Einval); }
    if p.iter().all(|&b| b == 0) { return Err(Errno::Einval); }
    if p.len() * 8 < DH_MIN_PRIME_BITS { return Err(Errno::Einval); }
    for v in [p, g, x] {
        if Mpi::from_be_bytes(v).bit_len() as usize > MPI_MAX_IMPORT_BITS { return Err(Errno::Einval); }
    }
    Ok(())
}

/// `base^private mod prime`, returned as a big-endian string whose width is
/// the modulus rounded UP to a whole number of limbs — the same width the
/// length query reports, so a caller that sized its buffer from the query
/// always has room. # C: O(bits(x) * limbs(p)^2)
pub fn compute(p: &[u8], g: &[u8], x: &[u8]) -> Result<Vec<u8>, Errno> {
    vet_inputs(p, g, x)?;
    let (mp, mg, mx) = (Mpi::from_be_bytes(p), Mpi::from_be_bytes(g), Mpi::from_be_bytes(x));
    let width = mp.limb_size();
    let val = mg.powm(&mx, &mp).ok_or(Errno::Einval)?;
    val.to_be_bytes(width).ok_or(Errno::Einval)
}

/// The output width `KEYCTL_DH_COMPUTE` reports for a length query, and the
/// exact number of bytes a non-derived computation writes. # C: O(len)
pub fn output_len(p: &[u8]) -> usize { Mpi::from_be_bytes(p).limb_size() }

/// Counter-mode key derivation (SP 800-108, fixed-input, no separate key):
/// the output is `H(BE32(1) || Z) || H(BE32(2) || Z) || …` truncated to the
/// requested length, where `Z` is the shared secret followed by the caller's
/// otherinfo. The counter is a 32-bit big-endian value starting at 1.
/// # C: O(outlen)
pub fn kdf_ctr(hash: Digest, z: &[u8], outlen: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(outlen);
    let mut counter: u32 = 1;
    while out.len() < outlen {
        let block = hash.digest(&[&counter.to_be_bytes(), z]);
        let take = core::cmp::min(block.len(), outlen - out.len());
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}
