// yescrypt ($y$) — module manifest. Real yescrypt KDF (scrypt + pwxform +
// Salsa20/8), ported from libxcrypt's alg-yescrypt-{opt,common}.c reference
// (not a re-implementation from memory of the spec — see each submodule's
// header for the exact reference function it mirrors).
//
// Module map:
//   b64      — byte-oriented crypt-b64 codec (salt/hash encoding)
//   params   — $y$ field codec (flavor/N/r/p/t/g) + YescryptParams
//   salsa    — Salsa20/8 core, classic BlockMix-Salsa8 (RFC-7914-verifiable)
//   pwxform  — yescrypt-RW's S-box block mixing (pwxform, blockmix_pwx*)
//   hmac     — HMAC-SHA256 + PBKDF2-HMAC-SHA256
//   smix     — SMix1/SMix2/SMix orchestration
//   kdf      — outer prehash/posthash wrapper + two-stage prehash + classic_scrypt
//
// Argon2id ($y$ is NOT Argon2id) is out of scope for this module — docs/59
// gap, not silently stubbed.
extern crate alloc;
use alloc::string::String;

pub mod b64;
pub mod params;
pub mod salsa;
pub mod pwxform;
pub mod hmac;
pub mod smix;
pub mod kdf;

use params::YescryptParams;

// Cheap (no KDF) parse of a `$y$<fields>$<salt>[$<hash>]` setting's fields
// + decoded salt + the verbatim prefix length (bytes up to and including
// the salt). Shared by `hash` and `setting_supported`.
fn parse_setting(setting: &[u8]) -> Option<(YescryptParams, usize, alloc::vec::Vec<u8>)> {
    let rest = setting.strip_prefix(b"$y$")?;
    let (params, field_len) = params::parse_fields(rest)?;
    let prefix_len = 3 + field_len;

    let saltstr = &rest[field_len..];
    let salt_end = saltstr.iter().position(|&c| c == b'$').unwrap_or(saltstr.len());
    let salt = b64::decode64(&saltstr[..salt_end], 64)?;

    Some((params, prefix_len + salt_end, salt))
}

/// Verify/compute: given `setting` = a `$y$<fields>$<salt>[$<hash>]` string
/// (the trailing `$<hash>` part, if present, is ignored — matching
/// yescrypt_r's "salt ends at the LAST '$'" contract, which is what makes a
/// full hash string a valid re-verification setting), compute the full
/// `$y$<fields>$<salt>$<hash>` string for `password`. `None` on a malformed
/// setting or an unsupported parameter combination (non-default pwxform
/// flavor, p!=1, ROM, hash-upgrade `g`).
/// # C: O(N*r)
pub fn hash(password: &[u8], setting: &[u8]) -> Option<String> {
    let (params, verbatim_len, salt) = parse_setting(setting)?;
    let hashbin = kdf::yescrypt_kdf(password, &salt, &params)?;

    let verbatim = &setting[..verbatim_len];
    let mut out = String::with_capacity(verbatim.len() + 1 + 43);
    for &b in verbatim { out.push(b as char); }
    out.push('$');
    for &c in &b64::encode64(&hashbin) { out.push(c as char); }
    Some(out)
}

/// Cheap setting-syntax + parameter-support check (no KDF run) — for
/// `crypt_checksalt`, which must not pay O(N*r) memory-hard work just to
/// validate a setting string.
/// # C: O(len(setting))
pub fn setting_supported(setting: &[u8]) -> bool {
    match parse_setting(setting) {
        Some((params, _, _)) => kdf::params_supported(&params),
        None => false,
    }
}

/// crypt_gensalt-shape `$y$` setting generator (gensalt_yescrypt_rn):
/// `count` 1..=11 selects N/r (0 defaults to 5); `rbytes` (16..=64, longer
/// truncated to 64) becomes the b64-encoded salt.
/// # C: O(len(rbytes))
pub fn gensalt(count: u32, rbytes: &[u8]) -> Option<String> {
    let rbytes = if rbytes.len() > 64 { &rbytes[..64] } else { rbytes };
    if count > 11 || rbytes.len() < 16 { return None; }
    let count = if count == 0 { 5 } else { count };
    let (r, n): (u32, u64) = if count < 3 { (8, 1u64 << (count + 9)) } else { (32, 1u64 << (count + 7)) };

    let params = YescryptParams { flags: params::YESCRYPT_RW_DEFAULTS, n, r, p: 1, t: 0, g: 0, nrom: 0 };
    let fields = params::encode_fields(&params)?;

    let mut out = String::with_capacity(3 + fields.len() + rbytes.len() * 2);
    out.push('$'); out.push('y'); out.push('$');
    for &c in &fields { out.push(c as char); }
    for &c in &b64::encode64(rbytes) { out.push(c as char); }
    Some(out)
}

#[cfg(test)]
mod tests;
