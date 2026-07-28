// `keyctl(2)` command dispatch — parse args, marshal user memory, call the
// `ops::*_core` that owns the command. No policy here.

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::ops;
use super::uapi::*;
use super::{cur_ctx, err, read_user_bytes, read_user_key_desc, read_user_key_type,
    write_user_capped, write_user_exact};

/// `sys_keyctl(op, arg2..arg5)` — slot 250.
///
/// Every command Linux implements without `CONFIG_KEY_DH_OPERATIONS`,
/// `CONFIG_ASYMMETRIC_KEY_TYPE` or `CONFIG_KEY_NOTIFICATIONS` is dispatched to
/// a real core. The instantiation family (`INSTANTIATE`, `INSTANTIATE_IOV`,
/// `NEGATE`, `REJECT`, `ASSUME_AUTHORITY`) reaches its Linux answer by the
/// Linux rule: each first resolves the target's instantiation authorisation
/// key via `key_get_instantiation_authkey`, which searches the caller's
/// keyrings for a `.request_key_auth` key and yields ENOKEY when there is
/// none. Authorisation keys are minted only by an in-flight `request_key`
/// upcall to `/sbin/request-key`; with no upcall helper there is never one to
/// find, so ENOKEY is the correct and complete answer rather than a swallowed
/// command. `KEYCTL_ASSUME_AUTHORITY(0)` — divest authority — is a real
/// success, and a negative id is EINVAL, both per `keyctl_assume_authority`.
/// # C: depends on op
pub fn sys_keyctl(args: &SyscallArgs) -> i64 {
    let c = cur_ctx();
    match args.a0 {
        KEYCTL_GET_KEYRING_ID => ops::get_keyring_id(&c, args.a1 as i32, args.a2 != 0),
        KEYCTL_JOIN_SESSION_KEYRING => {
            let name = if args.a1 == 0 { None }
                       else { match read_user_key_desc(args.a1) { Ok(s) => Some(s), Err(rv) => return rv } };
            ops::join_session(&c, name.as_deref())
        }
        KEYCTL_UPDATE => {
            let payload = match read_user_bytes(args.a2, args.a3) { Ok(v) => v, Err(rv) => return rv };
            ops::update_core(&c, args.a1 as i32, payload)
        }
        KEYCTL_REVOKE => ops::revoke_core(&c, args.a1 as i32),
        KEYCTL_CHOWN => ops::chown_core(&c, args.a1 as i32, args.a2 as u32, args.a3 as u32),
        KEYCTL_SETPERM => ops::setperm_core(&c, args.a1 as i32, args.a2 as u32),
        KEYCTL_DESCRIBE => {
            let s = match ops::describe_core(&c, args.a1 as i32) { Ok(s) => s, Err(rv) => return rv };
            write_user_exact(args.a2, args.a3, s.as_bytes())
        }
        KEYCTL_CLEAR => ops::clear_core(&c, args.a1 as i32),
        KEYCTL_LINK => ops::link_core(&c, args.a1 as i32, args.a2 as i32),
        KEYCTL_UNLINK => ops::unlink_core(&c, args.a1 as i32, args.a2 as i32),
        KEYCTL_SEARCH => {
            let key_type = match read_user_key_type(args.a2) { Ok(s) => s, Err(rv) => return rv };
            let description = match read_user_key_desc(args.a3) { Ok(s) => s, Err(rv) => return rv };
            ops::search_core(&c, args.a1 as i32, &key_type, &description, args.a4 as i32)
        }
        KEYCTL_READ => {
            let bytes = match ops::read_core(&c, args.a1 as i32) { Ok(b) => b, Err(rv) => return rv };
            write_user_capped(args.a2, args.a3, &bytes)
        }
        KEYCTL_SET_REQKEY_KEYRING => ops::set_reqkey_keyring(&c, args.a1 as i32),
        KEYCTL_SET_TIMEOUT => ops::set_timeout_core(&c, args.a1 as i32, args.a2 as u32 as u64),
        KEYCTL_ASSUME_AUTHORITY => assume_authority(args.a1 as i32),
        KEYCTL_GET_SECURITY => {
            let s = match ops::get_security_core(&c, args.a1 as i32) { Ok(s) => s, Err(rv) => return rv };
            write_user_capped(args.a2, args.a3, s.as_bytes())
        }
        KEYCTL_SESSION_TO_PARENT => ops::session_to_parent(&c, super::parent_info()),
        KEYCTL_INSTANTIATE | KEYCTL_INSTANTIATE_IOV | KEYCTL_NEGATE | KEYCTL_REJECT =>
            err(Errno::Enokey),
        KEYCTL_INVALIDATE => ops::invalidate_core(&c, args.a1 as i32),
        KEYCTL_GET_PERSISTENT => ops::get_persistent(&c, args.a1 as i32, args.a2 as i32),
        KEYCTL_RESTRICT_KEYRING => {
            if args.a3 != 0 && args.a2 == 0 { return err(Errno::Einval); }
            let ty = if args.a2 == 0 { None }
                     else { match read_user_key_type(args.a2) { Ok(s) => Some(s), Err(rv) => return rv } };
            ops::restrict_core(&c, args.a1 as i32, ty.as_deref())
        }
        KEYCTL_MOVE => ops::move_core(&c, args.a1 as i32, args.a2 as i32, args.a3 as i32, args.a4 as u32),
        KEYCTL_CAPABILITIES => capabilities(args.a1, args.a2),
        // `CONFIG_KEY_DH_OPERATIONS=n`, `CONFIG_ASYMMETRIC_KEY_TYPE=n` and
        // `CONFIG_KEY_NOTIFICATIONS=n` make Linux itself return EOPNOTSUPP
        // from the stubs in `security/keys/internal.h`. The advertised
        // `KEYCTL_CAPABILITIES` bits agree: neither DH, public-key nor
        // notification support is claimed.
        KEYCTL_DH_COMPUTE | KEYCTL_PKEY_QUERY | KEYCTL_PKEY_ENCRYPT | KEYCTL_PKEY_DECRYPT
        | KEYCTL_PKEY_SIGN | KEYCTL_PKEY_VERIFY | KEYCTL_WATCH_KEY => err(Errno::Eopnotsupp),
        _ => err(Errno::Eopnotsupp),
    }
}

/// `keyctl_assume_authority` — id 0 divests the authority the caller holds
/// (always a success; there is never one held here), a negative id is EINVAL,
/// and any real id needs an instantiation authorisation key that only a live
/// `request_key` upcall could have created. # C: O(1)
fn assume_authority(id: i32) -> i64 {
    if id < 0 { return err(Errno::Einval); }
    if id == 0 { return 0; }
    err(Errno::Enokey)
}

/// `keyctl_capabilities(buffer, buflen)`: copy up to `buflen` capability
/// bytes, zero-fill any remaining caller buffer, and return the FULL size so a
/// caller built against a longer array learns the true length. # C: O(buflen)
fn capabilities(buf_p: u64, buflen: u64) -> i64 {
    let full = KEYRINGS_CAPABILITIES.len();
    if buflen > 0 {
        let n = core::cmp::min(buflen as usize, full);
        if let Err(rv) = super::write_user_bytes(buf_p, &KEYRINGS_CAPABILITIES[..n]) { return rv; }
        if (buflen as usize) > n {
            let zeros = alloc::vec![0u8; buflen as usize - n];
            if let Err(rv) = super::write_user_bytes(buf_p + n as u64, &zeros) { return rv; }
        }
    }
    full as i64
}
