// The instantiation family: KEYCTL_INSTANTIATE, INSTANTIATE_IOV, NEGATE,
// REJECT and ASSUME_AUTHORITY.
//
// Every one of them is gated on the caller HOLDING the target key's
// authorisation token. Holding none at all is EPERM — the caller was never
// granted the right to answer this key. Holding a revoked one is EKEYREVOKED —
// it was, but the key has since been answered. Holding one for a DIFFERENT key
// is EPERM again, which is what stops a helper servicing request A from
// answering request B.
//
// Note what is NOT required: no permission on the target key itself. The token
// is the permission. That is why it must be minted only by the construction
// path and destroyed the instant the key is answered.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::{e, Ctx};
use super::super::auth;
use super::super::construct;
use super::super::store::STORE;
use super::super::uapi::*;

/// `keyctl_instantiate_key_common`: fill the key in and cache it in `ringid`.
///
/// The payload ceiling is checked BEFORE the token is consulted, so an absurd
/// length is rejected without revealing whether the caller had authority.
/// # C: O(N)
pub fn instantiate_core(c: &Ctx, id: i32, payload: Vec<u8>, ringid: i32) -> i64 {
    if payload.len() as u64 > KEY_MAX_PAYLOAD { return e(Errno::Einval); }
    let mut g = STORE.lock();
    let (authkey, a) = match auth::held_auth(&g, &c.t) { Ok(x) => x, Err(err) => return e(err) };
    if a.target != id { return e(Errno::Eperm); }
    let dest = match auth::instantiation_keyring(&mut g, ringid, &a, &c.t, c.now_ns) {
        Ok(d) => d, Err(rv) => return rv,
    };
    if let Err(rv) = construct::instantiate(&mut g, id, payload, dest, Some(authkey)) { return rv; }
    // The authority is spent the moment the key is answered: Linux drops
    // `cred->request_key_auth` so a helper cannot instantiate the same key
    // twice or keep the token alive past its purpose.
    auth::change_reqkey_auth(&mut g, c.t.tid, None);
    g.collect();
    0
}

/// `keyctl_reject_key`, and `keyctl_negate_key` which is this with `ENOKEY`.
///
/// The error is validated FIRST, before the token is even looked at: it has to
/// be a real errno a requester can be given, and not one of the restart
/// pseudo-errnos, which are kernel-internal and would be interpreted as "retry
/// the syscall" rather than as a failure.
/// # C: O(N)
pub fn reject_core(c: &Ctx, id: i32, timeout: u64, error: u32, ringid: i32) -> i64 {
    if error == 0 || error >= MAX_ERRNO
        || error == ERESTARTSYS_NR || error == ERESTARTNOINTR_NR
        || error == ERESTARTNOHAND_NR || error == ERESTART_RESTARTBLOCK_NR
    {
        return e(Errno::Einval);
    }
    let mut g = STORE.lock();
    let (authkey, a) = match auth::held_auth(&g, &c.t) { Ok(x) => x, Err(err) => return e(err) };
    if a.target != id { return e(Errno::Eperm); }
    let dest = match auth::instantiation_keyring(&mut g, ringid, &a, &c.t, c.now_ns) {
        Ok(d) => d, Err(rv) => return rv,
    };
    if let Err(rv) = construct::reject(&mut g, id, timeout, error as i32, dest, Some(authkey), c.now_ns) {
        return rv;
    }
    auth::change_reqkey_auth(&mut g, c.t.tid, None);
    g.collect();
    0
}

/// `keyctl_assume_authority`:
///   * a negative id is EINVAL — the special keyring ids name no key to assume
///     authority over;
///   * `0` divests whatever authority the caller holds, always a success;
///   * anything else must name a key the caller was handed a token for, found
///     by SEARCHING its own keyrings. Returns the token's serial.
/// # C: O(N)
pub fn assume_authority_core(c: &Ctx, id: i32) -> i64 {
    let mut g = STORE.lock();
    if id < 0 { return e(Errno::Einval); }
    if id == 0 { auth::change_reqkey_auth(&mut g, c.t.tid, None); return 0; }
    let authkey = match auth::get_instantiation_authkey(&g, id, &c.t, c.now_ns) {
        Ok(a) => a, Err(err) => return e(err),
    };
    auth::change_reqkey_auth(&mut g, c.t.tid, Some(authkey));
    authkey as i64
}

/// `KEYCTL_INSTANTIATE_IOV`'s segment-count contract, applied before any
/// user memory is touched: a NULL vector means zero segments, and more than
/// `UIO_MAXIOV` of them is EINVAL. Split out from the marshalling so the bound
/// is testable without user memory. # C: O(1)
pub fn vet_iov_count(have_ptr: bool, ioc: u64) -> Result<u64, i64> {
    let n = if have_ptr { ioc } else { 0 };
    if n > UIO_MAXIOV { return Err(e(Errno::Einval)); }
    Ok(n)
}
