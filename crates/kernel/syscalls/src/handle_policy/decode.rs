// `open_by_handle_at(2)` header validation + the `may_decode_fh` admission
// ladder.
//
// Decoding a handle SIDESTEPS the path walk, so it sidesteps every directory
// permission on the way to the object. The ladder below is what replaces that
// walk. Its ORDER is load-bearing and is asserted by the hosted suite:
// malformed handle (EINVAL) before the anchor fd (EBADF) before any capability
// (EPERM), so an unprivileged caller is never told "permission denied" for a
// mistake privilege would not have fixed.

use syscall::errno::Errno;

use vfs::export::fid::fid_len_for_type;
use super::flags::MAX_HANDLE_SZ;

/// `FILEID_USER_FLAGS_MASK` — the `handle_type` bits userspace may set.
pub const FILEID_USER_FLAGS_MASK: i32 = 0xffff_0000u32 as i32;
/// `FILEID_IS_CONNECTABLE` — the handle carries a parent and decode must
/// reconnect through it.
pub const FILEID_IS_CONNECTABLE: i32 = 0x10000;
/// `FILEID_IS_DIR` — the encoded object was a directory. Decode verifies it,
/// because reconnecting a directory and reconnecting a non-directory are
/// different operations.
pub const FILEID_IS_DIR: i32 = 0x20000;
/// `FILEID_VALID_USER_FLAGS`.
pub const FILEID_VALID_USER_FLAGS: i32 = FILEID_IS_CONNECTABLE | FILEID_IS_DIR;

/// `O_DIRECTORY`. The relaxed (non-`CAP_DAC_READ_SEARCH`) decode path is
/// restricted to it, so the API stays deterministic instead of sometimes
/// yielding a disconnected non-directory dentry.
pub const O_DIRECTORY: u32 = 0o200000;

/// `handle_to_path`'s header validation, run BEFORE the mount fd is resolved or
/// any capability is consulted: a malformed handle is EINVAL even for an
/// unprivileged caller with a bad fd.
///
/// `handle_bytes == 0` and `> MAX_HANDLE_SZ` are both EINVAL; a negative
/// `handle_type` is EINVAL; and `handle_type`'s user-flag bits must lie inside
/// `FILEID_VALID_USER_FLAGS`.
/// # C: O(1)
pub fn handle_header_check(handle_bytes: u32, handle_type: i32) -> Result<(), Errno> {
    if handle_bytes > MAX_HANDLE_SZ || handle_bytes == 0 { return Err(Errno::Einval); }
    if handle_type < 0 { return Err(Errno::Einval); }
    if handle_type & FILEID_USER_FLAGS_MASK & !FILEID_VALID_USER_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Drop the user-flag bits, leaving the filesystem-visible `handle_type`.
/// Linux does this before handing the handle to the backend, so a backend can
/// never see (and never has to mask) a flag the VFS layer owns.
/// # C: O(1)
pub fn strip_user_flags(handle_type: i32) -> i32 { handle_type & !FILEID_USER_FLAGS_MASK }

/// True when a validated header names a FID this kernel encodes, with the
/// payload length its type claims. A well-formed handle from another encoder
/// fails here; its errno is ESTALE at the caller, not EINVAL.
/// # C: O(1)
pub fn header_is_our_fid(handle_bytes: u32, handle_type: i32) -> bool {
    fid_len_for_type(strip_user_flags(handle_type)) == Some(handle_bytes)
}

/// The facts `may_decode_fh` weighs. Gathered by the slot file (which owns the
/// task, the anchor mount and the superblock) so the DECISION is a pure
/// function the hosted suite can drive through every branch.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MayDecodeFh {
    /// `capable(CAP_DAC_READ_SEARCH)` — the capability in the INITIAL user
    /// namespace, i.e. genuine global override.
    pub cap_dac_read_search: bool,
    /// The caller passed `O_DIRECTORY`.
    pub o_directory: bool,
    /// `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` — may the caller mount this
    /// filesystem? If so it could reach the object by mounting it afresh.
    pub sys_admin_over_sb_userns: bool,
    /// The anchor's mount is attached to a namespace (`is_mounted`).
    pub anchor_is_mounted: bool,
    /// `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)` — may the caller bind-mount
    /// the anchor? If so it could reach the object through the bind.
    pub sys_admin_over_mnt_ns: bool,
    /// A direct child mount at or under the anchor carries `MNT_LOCKED`, so a
    /// bind-mount would NOT in fact expose everything beneath it.
    pub has_locked_children: bool,
    /// `ns_capable(current_user_ns(), CAP_DAC_READ_SEARCH)` — the relaxed path
    /// still overrides DAC, only within the caller's own namespace.
    pub dac_read_search_in_user_ns: bool,
}

/// What the decode must additionally enforce once `may_decode_fh` allows it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct DecodeCtx {
    /// Walk the decoded object's ancestors and require each to be owned by an
    /// id mapped in the caller's user namespace. Clear for the global-capability
    /// path, whose holder may reach anything.
    pub check_perms: bool,
    /// The decoded object must additionally live UNDER the anchor. Set on the
    /// bind-mount leg: the caller's reach is the subtree it could have bound,
    /// not the whole filesystem.
    pub check_subtree: bool,
    /// `EXPORT_FH_DIR_ONLY` — decode must refuse a non-directory (ENOTDIR).
    pub dir_only: bool,
}

/// `may_decode_fh` — may this caller turn a handle into an fd?
///
/// The global-capability holder passes immediately with no further checks (an
/// empty [`DecodeCtx`]). Everyone else takes the relaxed path, whose premise is
/// "you could have reached this object anyway": either you may mount the
/// filesystem, or you may bind-mount the anchor and nothing locked is hiding a
/// part of it. That path is restricted to `O_DIRECTORY` and still demands the
/// DAC override inside the caller's own user namespace, and it hands back a
/// context that makes the decode re-verify ownership (and, on the bind leg,
/// containment) instead of trusting the handle.
/// # C: O(1)
pub fn may_decode_fh(f: MayDecodeFh) -> Result<DecodeCtx, Errno> {
    if f.cap_dac_read_search { return Ok(DecodeCtx::default()); }
    if !f.o_directory { return Err(Errno::Eperm); }
    let mut ctx = DecodeCtx::default();
    if f.sys_admin_over_sb_userns {
        ctx.check_perms = true;
    } else if f.anchor_is_mounted && f.sys_admin_over_mnt_ns && !f.has_locked_children {
        ctx.check_perms = true;
        ctx.check_subtree = true;
    } else {
        return Err(Errno::Eperm);
    }
    if !f.dac_read_search_in_user_ns { return Err(Errno::Eperm); }
    ctx.dir_only = true;
    Ok(ctx)
}
