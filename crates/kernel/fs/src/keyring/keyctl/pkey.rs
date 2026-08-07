// `KEYCTL_PKEY_*` argument marshalling: copy in the parameter block and the
// information string, call the core, copy out the result.

use ::pkey::Operation;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::super::ops::{pkey, Ctx};
use super::super::uapi::*;
use super::super::{err, key_string_from_bytes, read_user_bytes, read_user_key_cstr,
    write_user_bytes};

/// `keyctl(KEYCTL_PKEY_QUERY, key_id, 0, info, result)`.
///
/// The third argument is reserved and must be zero: it is checked before
/// anything else, so a caller passing a stale value is told so rather than
/// having it silently ignored. # C: O(log N + parse)
pub fn query(c: &Ctx, args: &SyscallArgs) -> i64 {
    if args.a2 != 0 { return err(Errno::Einval); }
    let info = match read_info(args.a3) { Ok(i) => i, Err(rv) => return rv };
    let q = match pkey::query_core(c, args.a1 as i32, &info) { Ok(q) => q, Err(rv) => return rv };
    let mut out = alloc::vec![0u8; PKEY_QUERY_SIZE];
    let mut ops: u32 = 0;
    if q.can_encrypt { ops |= KEYCTL_SUPPORTS_ENCRYPT; }
    if q.can_decrypt { ops |= KEYCTL_SUPPORTS_DECRYPT; }
    if q.can_sign    { ops |= KEYCTL_SUPPORTS_SIGN; }
    if q.can_verify  { ops |= KEYCTL_SUPPORTS_VERIFY; }
    put_u32(&mut out, PKEY_QUERY_SUPPORTED_OPS_OFFSET, ops);
    put_u32(&mut out, PKEY_QUERY_KEY_SIZE_OFFSET, q.key_size);
    put_u16(&mut out, PKEY_QUERY_MAX_DATA_SIZE_OFFSET, q.max_data_size);
    put_u16(&mut out, PKEY_QUERY_MAX_SIG_SIZE_OFFSET, q.max_sig_size);
    put_u16(&mut out, PKEY_QUERY_MAX_ENC_SIZE_OFFSET, q.max_enc_size);
    put_u16(&mut out, PKEY_QUERY_MAX_DEC_SIZE_OFFSET, q.max_dec_size);
    // The reserved words are written as zeroes rather than left untouched, so
    // a caller that reuses a stack structure cannot read its own stale bytes
    // back as though this kernel had set them.
    match write_user_bytes(args.a4, &out) { Ok(()) => 0, Err(rv) => rv }
}

/// `keyctl(KEYCTL_PKEY_{ENCRYPT,DECRYPT,SIGN}, params, info, in, out)`.
/// Returns the number of bytes written. # C: O(rsa)
pub fn eds(c: &Ctx, op: Operation, args: &SyscallArgs) -> i64 {
    let (key_id, in_len, out_len) = match read_params(args.a1) { Ok(p) => p, Err(rv) => return rv };
    let info = match read_info(args.a2) { Ok(i) => i, Err(rv) => return rv };
    let key = match pkey::load_key(c, key_id) { Ok(k) => k, Err(rv) => return rv };
    let q = match key.query(&info.encoding, info.hash.as_deref()) {
        Ok(q) => q, Err(e) => return err(pkey::errno_for(e)),
    };
    if let Err(e) = pkey::vet_lengths(op, &q, in_len, out_len) { return err(e); }
    let input = match read_user_bytes(args.a3, in_len) { Ok(v) => v, Err(rv) => return rv };
    let produced = match pkey::eds_core(&key, op, &info, &input, fill_random) {
        Ok(v) => v, Err(rv) => return rv,
    };
    // The declared length is only an upper-bound admission check. The actual
    // copy width is the key operation's result, which is the ABI this command
    // has always exposed to callers that size their output from QUERY.
    match write_user_bytes(args.a4, &produced) { Ok(()) => produced.len() as i64, Err(rv) => rv }
}

/// `keyctl(KEYCTL_PKEY_VERIFY, params, info, data, sig)` — 0 when the
/// signature is this key's over this data. # C: O(rsa)
pub fn verify(c: &Ctx, args: &SyscallArgs) -> i64 {
    let (key_id, in_len, in2_len) = match read_params(args.a1) { Ok(p) => p, Err(rv) => return rv };
    let info = match read_info(args.a2) { Ok(i) => i, Err(rv) => return rv };
    let key = match pkey::load_key(c, key_id) { Ok(k) => k, Err(rv) => return rv };
    let q = match key.query(&info.encoding, info.hash.as_deref()) {
        Ok(q) => q, Err(e) => return err(pkey::errno_for(e)),
    };
    if let Err(e) = pkey::vet_lengths(Operation::Verify, &q, in_len, in2_len) { return err(e); }
    let digest = match read_user_bytes(args.a3, in_len) { Ok(v) => v, Err(rv) => return rv };
    let sig = match read_user_bytes(args.a4, in2_len) { Ok(v) => v, Err(rv) => return rv };
    match pkey::verify_core(&key, &info, &digest, &sig) { Ok(()) => 0, Err(rv) => rv }
}

/// Copy `struct keyctl_pkey_params`, returning the key serial and the two
/// declared lengths. # C: O(1)
fn read_params(p: u64) -> Result<(i32, u64, u64), i64> {
    let raw = read_user_bytes(p, PKEY_PARAMS_SIZE)?;
    let word = |off: usize| u32::from_ne_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
    Ok((word(PKEY_PARAMS_KEY_ID_OFFSET) as i32,
        word(PKEY_PARAMS_IN_LEN_OFFSET) as u64,
        word(PKEY_PARAMS_OUT_LEN_OFFSET) as u64))
}

/// Copy and parse the supplementary information string. A NULL pointer is a
/// fault, not an empty string: the argument is not optional at the ABI.
/// # C: O(len)
fn read_info(p: u64) -> Result<pkey::Info, i64> {
    let bytes = read_user_key_cstr(p, PKEY_INFO_MAX)?;
    let s = key_string_from_bytes(&bytes);
    pkey::parse_info(&s).map_err(err)
}

/// Padding entropy for the encryption encoding. # C: O(n)
fn fill_random(buf: &mut [u8]) { crng::fill(buf); }

fn put_u32(out: &mut [u8], off: usize, v: u32) { out[off..off + 4].copy_from_slice(&v.to_ne_bytes()); }
fn put_u16(out: &mut [u8], off: usize, v: u16) { out[off..off + 2].copy_from_slice(&v.to_ne_bytes()); }
