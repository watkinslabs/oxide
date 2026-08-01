// `keyctl(2)` command dispatch — parse args, marshal user memory, call the
// `ops::*_core` that owns the command. No policy here.

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::ops;
use super::uapi::*;

use super::{cur_ctx, err, read_user_bytes, read_user_key_desc, read_user_key_type,
    write_user_capped, write_user_exact};

mod dh;

/// `sys_keyctl(op, arg2..arg5)` — slot 250.
///
/// Every command Linux implements without `CONFIG_KEY_DH_OPERATIONS`,
/// `CONFIG_ASYMMETRIC_KEY_TYPE` or `CONFIG_KEY_NOTIFICATIONS` is dispatched to
/// a real core, including the instantiation family — `INSTANTIATE`,
/// `INSTANTIATE_IOV`, `NEGATE`, `REJECT` and `ASSUME_AUTHORITY` — which is what
/// `/sbin/request-key` uses to answer a key the kernel asked it to build.
/// # C: depends on op
pub fn sys_keyctl(args: &SyscallArgs) -> i64 {
    let c = cur_ctx();
    match args.a0 {
        KEYCTL_GET_KEYRING_ID => ops::get_keyring_id(&c, args.a1 as i32, args.a2 != 0),
        KEYCTL_JOIN_SESSION_KEYRING => {
            let name = if args.a1 == 0 { None }
                       else { match read_user_key_desc(args.a1) { Ok(s) => Some(s), Err(rv) => return rv } };
            if let Err(e) = ops::vet_session_name(name.as_deref()) { return err(e); }
            ops::join_session(&c, name.as_deref())
        }
        KEYCTL_UPDATE => {
            // `keyctl_update_key` bounds the update payload at ONE PAGE, an
            // order of magnitude below what `add_key` accepts, and rejects a
            // longer one before any copy.
            if args.a3 > KEYCTL_UPDATE_MAX_PAYLOAD { return err(Errno::Einval); }
            let payload = match read_user_bytes(args.a2, args.a3) { Ok(v) => v, Err(rv) => return rv };
            ops::update_core(&c, args.a1 as i32, payload, args.a2 != 0)
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
            // A NULL buffer is a length query, and the read method is then
            // asked for the length with a zero buffer length — which is what
            // the keyring type's 4-byte-alignment rule is applied to.
            let buflen = if args.a2 == 0 { 0 } else { args.a3 };
            let bytes = match ops::read_core(&c, args.a1 as i32, buflen) { Ok(b) => b, Err(rv) => return rv };
            write_user_capped(args.a2, args.a3, &bytes)
        }
        KEYCTL_SET_REQKEY_KEYRING => ops::set_reqkey_keyring(&c, args.a1 as i32),
        KEYCTL_SET_TIMEOUT => ops::set_timeout_core(&c, args.a1 as i32, args.a2 as u32 as u64),
        KEYCTL_ASSUME_AUTHORITY => ops::assume_authority_core(&c, args.a1 as i32),
        KEYCTL_GET_SECURITY => {
            let s = match ops::get_security_core(&c, args.a1 as i32) { Ok(s) => s, Err(rv) => return rv };
            write_user_capped(args.a2, args.a3, s.as_bytes())
        }
        KEYCTL_SESSION_TO_PARENT => ops::session_to_parent(&c, super::parent_info()),
        KEYCTL_INSTANTIATE => {
            // A NULL pointer or a zero length instantiates with an EMPTY
            // payload rather than faulting: `keyctl_instantiate_key` drops the
            // iterator when `!plen`, which is how a type with no payload at all
            // is instantiated.
            if args.a3 > KEY_MAX_PAYLOAD { return err(Errno::Einval); }
            let payload = match read_user_bytes(args.a2, args.a3) { Ok(v) => v, Err(rv) => return rv };
            ops::instantiate_core(&c, args.a1 as i32, payload, args.a4 as i32)
        }
        KEYCTL_INSTANTIATE_IOV => {
            let n = match ops::vet_iov_count(args.a2 != 0, args.a3) { Ok(n) => n, Err(rv) => return rv };
            let payload = match super::read_user_iov(args.a2, n) { Ok(v) => v, Err(rv) => return rv };
            ops::instantiate_core(&c, args.a1 as i32, payload, args.a4 as i32)
        }
        // NEGATE is REJECT with ENOKEY — the plain "I could not build this".
        KEYCTL_NEGATE => ops::reject_core(&c, args.a1 as i32, args.a2 as u32 as u64,
            Errno::Enokey.as_i32() as u32, args.a3 as i32),
        KEYCTL_REJECT => ops::reject_core(&c, args.a1 as i32, args.a2 as u32 as u64,
            args.a3 as u32, args.a4 as i32),
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
        KEYCTL_DH_COMPUTE => dh::dh_compute(&c, args),
        // The public-key and key-notification command families are not built
        // here yet; the `KEYCTL_CAPABILITIES` bits below are computed from the
        // same facts, so a caller that probes before use is told exactly what
        // it will get.
        KEYCTL_PKEY_QUERY | KEYCTL_PKEY_ENCRYPT | KEYCTL_PKEY_DECRYPT
        | KEYCTL_PKEY_SIGN | KEYCTL_PKEY_VERIFY | KEYCTL_WATCH_KEY => err(Errno::Eopnotsupp),
        _ => err(Errno::Eopnotsupp),
    }
}

/// The capability bytes this build reports.
///
/// Each optional bit is taken from the module that IMPLEMENTS the feature
/// (`ops::dh::SUPPORTED` and friends), never from a list kept alongside the
/// dispatch: a second list is a second truth, and the failure it produces —
/// a bit claiming a command that answers EOPNOTSUPP, or a working command no
/// caller probes for — is silent in both directions. The unconditional bits
/// name commands this kernel has no build option to omit.
/// # C: O(1)
pub(super) fn keyrings_capabilities() -> [u8; KEYCTL_CAPS_BYTES] {
    let mut b0 = KEYCTL_CAPS0_CAPABILITIES | KEYCTL_CAPS0_PERSISTENT_KEYRINGS
        | KEYCTL_CAPS0_BIG_KEY | KEYCTL_CAPS0_INVALIDATE | KEYCTL_CAPS0_RESTRICT_KEYRING
        | KEYCTL_CAPS0_MOVE;
    let b1 = KEYCTL_CAPS1_NS_KEYRING_NAME | KEYCTL_CAPS1_NS_KEY_TAG;
    if ops::dh::SUPPORTED { b0 |= KEYCTL_CAPS0_DIFFIE_HELLMAN; }
    [b0, b1]
}

/// `keyctl_capabilities(buffer, buflen)`: copy up to `buflen` capability
/// bytes, zero-fill any remaining caller buffer, and return the FULL size so a
/// caller built against a longer array learns the true length. # C: O(buflen)
fn capabilities(buf_p: u64, buflen: u64) -> i64 {
    let caps = keyrings_capabilities();
    let full = caps.len();
    if buflen > 0 {
        let n = core::cmp::min(buflen as usize, full);
        if let Err(rv) = super::write_user_bytes(buf_p, &caps[..n]) { return rv; }
        if (buflen as usize) > n {
            let zeros = alloc::vec![0u8; buflen as usize - n];
            if let Err(rv) = super::write_user_bytes(buf_p + n as u64, &zeros) { return rv; }
        }
    }
    full as i64
}
