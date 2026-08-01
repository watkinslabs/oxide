// `KEYCTL_DH_COMPUTE` argument marshalling. Copy-in, call the core, copy-out —
// plus the one thing only this layer can express: the ORDER the two user
// structures are copied in relative to the checks on their contents.

use alloc::vec::Vec;

use crypt::Digest;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::super::ops::{dh, Ctx};
use super::super::uapi::*;
use super::super::{err, read_user_bytes, read_user_key_cstr, write_user_bytes};

/// The derivation request, after its user structure has been copied and vetted.
struct KdfRequest {
    hash: Digest,
    otherinfo_ptr: u64,
    otherinfo_len: u64,
}

/// `keyctl(KEYCTL_DH_COMPUTE, params, buffer, buflen, kdf)`.
///
/// Argument handling, in the order the errors are produced — the order matters
/// because a caller distinguishes "you passed me nonsense" from "your buffer is
/// unreadable" by which errno arrives first:
///   1. a non-NULL `kdf` is copied FIRST, so a bad derivation structure is
///      EFAULT even when the rest of the call is malformed;
///   2. a NULL `params`, or a nonzero `buflen` with a NULL buffer, is EINVAL;
///   3. `params` is copied (EFAULT);
///   4. the derivation request is vetted: any reserved word set is EINVAL, an
///      output or otherinfo length past its ceiling is EMSGSIZE, then the hash
///      name is copied (EFAULT / EINVAL if unterminated) and resolved (ENOENT
///      for a digest this kernel does not implement);
///   5. the three keys are read — modulus, base, private value, in that order;
///   6. the parameters are vetted and the exponentiation runs;
///   7. WITHOUT derivation a `buflen` of zero is a length query and a buffer
///      too small for the whole value is EOVERFLOW — the value is never
///      truncated. WITH derivation the output is exactly `buflen` bytes.
/// # C: O(bits(private) * limbs(prime)^2)
pub fn dh_compute(c: &Ctx, args: &SyscallArgs) -> i64 {
    let (params_p, buf_p, buflen, kdf_p) = (args.a1, args.a2, args.a3, args.a4);

    let kdf_raw = if kdf_p == 0 { None } else {
        match read_user_bytes(kdf_p, KDF_PARAMS_SIZE) { Ok(v) => Some(v), Err(rv) => return rv }
    };
    if params_p == 0 || (buf_p == 0 && buflen != 0) { return err(Errno::Einval); }
    let params = match read_user_bytes(params_p, DH_PARAMS_SIZE) { Ok(v) => v, Err(rv) => return rv };
    let private = i32::from_ne_bytes([params[0], params[1], params[2], params[3]]);
    let prime   = i32::from_ne_bytes([params[4], params[5], params[6], params[7]]);
    let base    = i32::from_ne_bytes([params[8], params[9], params[10], params[11]]);

    let kdf = match kdf_raw {
        None => None,
        Some(raw) => match vet_kdf(&raw, buflen) { Ok(k) => Some(k), Err(rv) => return rv },
    };

    let p = match dh::dh_data_from_key(c, prime)   { Ok(v) => v, Err(rv) => return rv };
    let g = match dh::dh_data_from_key(c, base)    { Ok(v) => v, Err(rv) => return rv };
    let x = match dh::dh_data_from_key(c, private) { Ok(v) => v, Err(rv) => return rv };

    if let Err(e) = dh::vet_inputs(&p, &g, &x) { return err(e); }
    let outlen = dh::output_len(&p) as u64;

    match kdf {
        None => {
            // A zero-length buffer asks how wide the answer is.
            if buflen == 0 { return outlen as i64; }
            if outlen > buflen { return err(Errno::Eoverflow); }
            let secret = match dh::compute(&p, &g, &x) { Ok(v) => v, Err(e) => return err(e) };
            match write_user_bytes(buf_p, &secret) { Ok(()) => outlen as i64, Err(rv) => rv }
        }
        Some(k) => {
            let secret = match dh::compute(&p, &g, &x) { Ok(v) => v, Err(e) => return err(e) };
            // The otherinfo is copied only once the secret exists, so an
            // unreadable otherinfo pointer cannot pre-empt a key error.
            let mut z: Vec<u8> = secret;
            match read_user_bytes(k.otherinfo_ptr, k.otherinfo_len) {
                Ok(oi) => z.extend_from_slice(&oi),
                Err(rv) => return rv,
            }
            let out = dh::kdf_ctr(k.hash, &z, buflen as usize);
            match write_user_bytes(buf_p, &out) { Ok(()) => buflen as i64, Err(rv) => rv }
        }
    }
}

/// Vet a copied `struct keyctl_kdf_params`. # C: O(1)
fn vet_kdf(raw: &[u8], buflen: u64) -> Result<KdfRequest, i64> {
    let word = |off: u64| -> u32 {
        let i = off as usize;
        u32::from_ne_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]])
    };
    let ptr = |off: u64| -> u64 {
        let i = off as usize;
        u64::from_ne_bytes(raw[i..i + 8].try_into().expect("eight bytes inside the copied structure"))
    };
    // The reserved words are a forward-compatibility contract: a caller that
    // sets one is asking for a facility this kernel has no definition of, so
    // the call is refused rather than silently ignoring the request.
    for i in 0..KDF_SPARE_WORDS {
        if word(KDF_SPARE_OFFSET + i * 4) != 0 { return Err(err(Errno::Einval)); }
    }
    let otherinfo_len = word(KDF_OTHERINFO_LEN_OFFSET) as u64;
    if buflen > KEYCTL_KDF_MAX_OUTPUT_LEN || otherinfo_len > KEYCTL_KDF_MAX_OI_LEN {
        return Err(err(Errno::Emsgsize));
    }
    let name_bytes = read_user_key_cstr(ptr(KDF_HASHNAME_OFFSET), CRYPTO_MAX_ALG_NAME)?;
    let name = super::super::key_string_from_bytes(&name_bytes);
    let hash = Digest::by_name(&name).ok_or(err(Errno::Enoent))?;
    Ok(KdfRequest { hash, otherinfo_ptr: ptr(KDF_OTHERINFO_OFFSET), otherinfo_len })
}
