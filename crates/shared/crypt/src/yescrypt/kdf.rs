// yescrypt_kdf_body / yescrypt_kdf orchestration (alg-yescrypt-opt.c): the
// outer prehash/posthash HMAC wrapper, PBKDF2(B) mixing, and the two-stage
// "compute a cheap N>>6 prehash key first" optimization used whenever
// N/p>=0x100 && N/p*r>=0x20000 (true for the real-world "j9T" default
// params: N=4096,r=32 -> N*r=131072=0x20000). `buflen` is always 32 in our
// usage (yescrypt_r always asks for a 32-byte hash, both for the inner
// prehash sub-call and the outer main call), which lets us drop the
// reference's `buflen<sizeof(dk)` branch entirely (never taken here).
extern crate alloc;
use alloc::vec::Vec;
use super::hmac::{hmac_sha256, pbkdf2_sha256};
use super::params::{YescryptParams, YESCRYPT_RW, flags_supported};
use super::smix;

const YESCRYPT_PREHASH_KEY: &[u8] = b"yescrypt-prehash";

/// Is `params` a combination this KDF can actually compute? Unsupported
/// pwxform flavor, p!=1 (see smix.rs module doc), g!=0 (hash upgrades,
/// unimplemented upstream too), or NROM!=0 (no ROM support) are all
/// rejected here — cheaply, without running any KDF work — so callers
/// like `crypt_checksalt` can validate a setting without paying its O(N*r)
/// cost.
/// # C: O(1)
pub fn params_supported(params: &YescryptParams) -> bool {
    flags_supported(params.flags)
        && params.g == 0 && params.nrom == 0 && params.p == 1
        && params.r != 0 && params.n > 3 && (params.n & (params.n - 1)) == 0
        && params.n <= u32::MAX as u64
}

/// Compute the 32-byte yescrypt/scrypt KDF output for `passwd`+`salt` under
/// `params`. Returns `None` for any unsupported parameter combination (see
/// `params_supported`).
/// # C: O(N*r) dominated by the memory-hard SMix pass(es)
pub fn yescrypt_kdf(passwd: &[u8], salt: &[u8], params: &YescryptParams) -> Option<[u8; 32]> {
    if !params_supported(params) { return None; }

    let rw = params.flags & YESCRYPT_RW != 0;
    let n = params.n as u32;

    if rw && n >= 0x100 && (n as u64) * (params.r as u64) >= 0x20000 {
        let inner = YescryptParams { n: (n >> 6).max(4) as u64, t: 0, ..params.clone() };
        let dk = yescrypt_kdf_body(passwd, salt, &inner, true)?;
        yescrypt_kdf_body(&dk, salt, params, false)
    } else {
        yescrypt_kdf_body(passwd, salt, params, false)
    }
}

/// # C: O(N*r)
///
/// Reference note (the source of a real bug found via differential testing):
/// yescrypt_kdf_body's C `passwd` POINTER is reassigned to alias its local
/// `sha256` scratch buffer once prehash runs (`passwd = sha256;`), and that
/// buffer is mutated AGAIN right after — `memcpy(sha256, B, 32)` — and, for
/// RW, a third time inside smix()'s S-box-seed HMAC step. Every USE of
/// `passwd` after those points therefore observes the MUTATED value, not
/// the original prehash HMAC result. We model the aliasing explicitly via
/// `running_key`: `first_key` feeds only the first PBKDF2 call (B); the
/// final PBKDF2 call (and nothing else) uses `running_key` post-smix.
fn yescrypt_kdf_body(passwd: &[u8], salt: &[u8], params: &YescryptParams, is_prehash_call: bool) -> Option<[u8; 32]> {
    let r = params.r as usize;
    let n = params.n as u32;
    if (n & (n - 1)) != 0 || n <= 3 { return None; }
    let rw = params.flags & YESCRYPT_RW != 0;
    let b_size = 128 * r; // p==1

    let mut running_key = [0u8; 32];
    let first_key: &[u8] = if params.flags != 0 {
        let key_len = if is_prehash_call { 16 } else { 8 };
        running_key = hmac_sha256(&YESCRYPT_PREHASH_KEY[..key_len], passwd);
        &running_key[..]
    } else {
        passwd
    };

    let mut b = pbkdf2_sha256(first_key, salt, 1, b_size);

    if params.flags != 0 { running_key.copy_from_slice(&b[..32]); }

    smix::smix(&mut b, r, n, params.t, rw, &mut running_key);

    let eff_passwd: &[u8] = if params.flags != 0 { &running_key[..] } else { passwd };
    let mut buf = pbkdf2_sha256(eff_passwd, &b, 1, 32);

    // SCRAM-like posthash (ClientKey/StoredKey), skipped for the inner
    // prehash sub-call (flags & YESCRYPT_PREHASH in the reference).
    if params.flags != 0 && !is_prehash_call {
        let client_key = hmac_sha256(&buf, b"Client Key");
        let stored_key = crate::sha256::sha256(&client_key);
        buf.copy_from_slice(&stored_key);
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&buf[..32]);
    Some(result)
}

/// Reference (unmodified) RFC 7914 classic scrypt — used only by hosted
/// tests to validate blockmix_salsa8/smix1/smix2's shared classic path
/// against the RFC's published vectors, independent of yescrypt's own
/// prehash/posthash wrapper and pwxform machinery.
/// # C: O(N*r*p)
pub fn classic_scrypt(passwd: &[u8], salt: &[u8], n: u32, r: usize, p: u32, dklen: usize) -> Vec<u8> {
    let mut b = pbkdf2_sha256(passwd, salt, 1, 128 * r * p as usize);
    let mut dummy = [0u8; 32];
    for i in 0..p as usize {
        smix::smix(&mut b[i * 128 * r..(i + 1) * 128 * r], r, n, 0, false, &mut dummy);
    }
    pbkdf2_sha256(passwd, &b, 1, dklen)
}
