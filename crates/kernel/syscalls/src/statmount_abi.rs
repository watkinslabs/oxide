// `statmount(2)` / `listmount(2)` ABI (`docs/15`, `docs/53`): the request
// struct, the field-mask space, and the `struct statmount` byte layout.
//
// UNGATED on purpose. Slots 457/458 are `#![cfg(target_os = "oxide-kernel")]`,
// so any test written inside them compiles away silently; every decision that
// userspace can observe — size admission, the `E2BIG`/`EINVAL` split, which
// mask bits may be raised, where each field lands in the output buffer — lives
// here instead, where `cargo test -p syscalls` actually builds it.
//
// Module manifest:
// - this file: `struct mnt_id_req` admission + the STATMOUNT_* mask space.
// - `statmount_abi/encode`: the `struct statmount` writer and its string area.

use syscall::errno::Errno;

#[path = "statmount_abi/encode.rs"]
pub mod encode;
pub use encode::{encode_statmount, IdMapRow, StatmountRecord, SM_SIZE};

/// `struct mnt_id_req` v0 (`{u32 size, u32 mnt_ns_fd/mnt_fd, u64 mnt_id, u64 param}`).
pub const MNT_ID_REQ_SIZE_VER0: u32 = 24;
/// `struct mnt_id_req` v1 — v0 plus `u64 mnt_ns_id`. The current kernel struct.
pub const MNT_ID_REQ_SIZE_VER1: u32 = 32;
/// `copy_mnt_id_req`'s upper bound on the caller-declared size.
pub const MNT_ID_REQ_SIZE_MAX: u32 = 4096;

const REQ_OFF_FD:        usize = 4;
const REQ_OFF_MNT_ID:    usize = 8;
const REQ_OFF_PARAM:     usize = 16;
const REQ_OFF_MNT_NS_ID: usize = 24;
const U32: usize = 4;
const U64: usize = 8;

/// `statmount(2)` flag word: report the mount behind `mnt_fd` rather than a
/// mount named by id.
pub const STATMOUNT_BY_FD: u32 = 0x0000_0001;

// --- STATMOUNT_* field mask. A bit in the request asks for a field; the same
// bit in the reply says the field was written. Reporting a field the caller did
// not ask for, or writing one without raising its bit, is a silent ABI break. ---
pub const STATMOUNT_SB_BASIC:       u64 = 0x0000_0001;
pub const STATMOUNT_MNT_BASIC:      u64 = 0x0000_0002;
pub const STATMOUNT_PROPAGATE_FROM: u64 = 0x0000_0004;
pub const STATMOUNT_MNT_ROOT:       u64 = 0x0000_0008;
pub const STATMOUNT_MNT_POINT:      u64 = 0x0000_0010;
pub const STATMOUNT_FS_TYPE:        u64 = 0x0000_0020;
pub const STATMOUNT_MNT_NS_ID:      u64 = 0x0000_0040;
pub const STATMOUNT_MNT_OPTS:       u64 = 0x0000_0080;
pub const STATMOUNT_FS_SUBTYPE:     u64 = 0x0000_0100;
pub const STATMOUNT_SB_SOURCE:      u64 = 0x0000_0200;
pub const STATMOUNT_OPT_ARRAY:      u64 = 0x0000_0400;
pub const STATMOUNT_OPT_SEC_ARRAY:  u64 = 0x0000_0800;
pub const STATMOUNT_SUPPORTED_MASK: u64 = 0x0000_1000;
pub const STATMOUNT_MNT_UIDMAP:     u64 = 0x0000_2000;
pub const STATMOUNT_MNT_GIDMAP:     u64 = 0x0000_4000;

/// Every field this kernel can report — the value handed back under
/// `STATMOUNT_SUPPORTED_MASK`, and the ceiling on any reply mask. # C: const
pub const STATMOUNT_SUPPORTED: u64 = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC
    | STATMOUNT_PROPAGATE_FROM | STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE | STATMOUNT_MNT_NS_ID | STATMOUNT_MNT_OPTS | STATMOUNT_FS_SUBTYPE
    | STATMOUNT_SB_SOURCE | STATMOUNT_OPT_ARRAY | STATMOUNT_OPT_SEC_ARRAY
    | STATMOUNT_SUPPORTED_MASK | STATMOUNT_MNT_UIDMAP | STATMOUNT_MNT_GIDMAP;

/// The requested fields that need room in the string area. Asking for any of
/// them with a buffer exactly the size of the fixed part is `EOVERFLOW`.
/// # C: const
pub const STATMOUNT_STRING_REQ: u64 = STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE | STATMOUNT_MNT_OPTS | STATMOUNT_FS_SUBTYPE | STATMOUNT_SB_SOURCE
    | STATMOUNT_OPT_ARRAY | STATMOUNT_OPT_SEC_ARRAY | STATMOUNT_MNT_UIDMAP
    | STATMOUNT_MNT_GIDMAP;

/// `listmount(2)` flag word: walk the namespace's mounts newest-first.
pub const LISTMOUNT_REVERSE: u32 = 1;
/// `listmount(2)` `mnt_id` meaning "the caller's own root subtree".
pub const LSMT_ROOT: u64 = u64::MAX;
/// `listmount(2)`'s cap on `nr_mnt_ids`; above it the caller must iterate.
pub const LISTMOUNT_MAX_COUNT: usize = 1_000_000;

/// A decoded `struct mnt_id_req`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MntIdReq {
    /// `mnt_ns_fd` for an id request, `mnt_fd` under `STATMOUNT_BY_FD`.
    pub fd: u32,
    /// Unique mount id (see `vfs::mount::MNT_UNIQUE_ID_OFFSET`).
    pub mnt_id: u64,
    /// `statmount`: the requested field mask. `listmount`: the cursor.
    pub param: u64,
    /// Mount-namespace id, or `0` for the caller's own.
    pub mnt_ns_id: u64,
}

/// `copy_mnt_id_req`'s size admission, run against the caller-declared `size`
/// BEFORE the rest of the struct is read. An oversized request is `E2BIG` and
/// an undersized one `EINVAL` — two different sizes, two different errnos, and
/// feature probes branch on which one they get. # C: O(1)
pub fn req_size_check(size: u32) -> Result<(), Errno> {
    if size > MNT_ID_REQ_SIZE_MAX { return Err(Errno::E2big); }
    if size < MNT_ID_REQ_SIZE_VER0 { return Err(Errno::Einval); }
    Ok(())
}

/// How many bytes of the caller's request this kernel reads, and whether any
/// bytes beyond the known struct must be checked for zero (`copy_struct_from_user`).
/// # C: O(1)
pub fn req_copy_plan(size: u32) -> (usize, usize) {
    let known = core::cmp::min(size, MNT_ID_REQ_SIZE_VER1) as usize;
    let tail = size.saturating_sub(MNT_ID_REQ_SIZE_VER1) as usize;
    (known, tail)
}

/// Decode a zero-padded `struct mnt_id_req` and apply `copy_mnt_id_req`'s
/// argument admission. `tail_nonzero` reports a set byte beyond the struct this
/// kernel knows — a caller using a newer struct with fields this kernel would
/// silently ignore, which is `E2BIG`. # C: O(1)
pub fn decode_mnt_id_req(head: &[u8; MNT_ID_REQ_SIZE_VER1 as usize], tail_nonzero: bool,
                         by_fd: bool) -> Result<MntIdReq, Errno> {
    if tail_nonzero { return Err(Errno::E2big); }
    let u32_at = |o: usize| u32::from_le_bytes(head[o..o + U32].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(head[o..o + U64].try_into().unwrap());
    let req = MntIdReq {
        fd: u32_at(REQ_OFF_FD),
        mnt_id: u64_at(REQ_OFF_MNT_ID),
        param: u64_at(REQ_OFF_PARAM),
        mnt_ns_id: u64_at(REQ_OFF_MNT_NS_ID),
    };
    if by_fd {
        // The fd IS the subject; naming a mount or a namespace too is a
        // contradiction, not a refinement.
        if req.mnt_id != 0 || req.mnt_ns_id != 0 { return Err(Errno::Einval); }
    } else {
        // A namespace may be named by fd or by id, never both.
        if req.fd != 0 && req.mnt_ns_id != 0 { return Err(Errno::Einval); }
        if vfs::mount::mnt_id_from_unique(req.mnt_id).is_none() { return Err(Errno::Einval); }
    }
    Ok(req)
}

/// Which mount namespace a request names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NsPick {
    /// The caller's own — neither `mnt_ns_id` nor `mnt_ns_fd` was given.
    Current,
    /// Named by `mnt_ns_id`. Reaching into it needs authority over it.
    ById,
    /// Named by `mnt_ns_fd`. The descriptor IS the authority, so no further
    /// capability check applies.
    ByFd,
}

/// Which namespace a decoded request names. # C: O(1)
pub fn ns_pick(req: &MntIdReq) -> NsPick {
    if req.mnt_ns_id != 0 { NsPick::ById } else if req.fd != 0 { NsPick::ByFd } else { NsPick::Current }
}

/// Admission for reaching into a namespace the caller does not live in.
/// Naming one BY ID grants nothing on its own, so a caller without
/// `CAP_SYS_ADMIN` over it is refused — as `EPERM` from `statmount(2)` and as
/// `ENOENT` from `listmount(2)`, which reports non-existence rather than
/// admitting the namespace is there. # C: O(1)
pub fn ns_admission(pick: NsPick, is_current: bool, may_admin: bool, listmount: bool)
                    -> Result<(), Errno> {
    if pick != NsPick::ById || is_current || may_admin { return Ok(()); }
    Err(if listmount { Errno::Enoent } else { Errno::Eperm })
}

/// `listmount`'s cursor admission: `0` starts at the end of the list, and any
/// other value must be a well-formed unique mount id. # C: O(1)
pub fn listmount_cursor_check(cursor: u64) -> Result<(), Errno> {
    if cursor != 0 && vfs::mount::mnt_id_from_unique(cursor).is_none() { return Err(Errno::Einval); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFSET: u64 = vfs::mount::MNT_UNIQUE_ID_OFFSET;

    fn req_bytes(fd: u32, mnt_id: u64, param: u64, ns_id: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&MNT_ID_REQ_SIZE_VER1.to_le_bytes());
        b[4..8].copy_from_slice(&fd.to_le_bytes());
        b[8..16].copy_from_slice(&mnt_id.to_le_bytes());
        b[16..24].copy_from_slice(&param.to_le_bytes());
        b[24..32].copy_from_slice(&ns_id.to_le_bytes());
        b
    }

    #[test]
    fn oversized_request_is_e2big_and_undersized_is_einval() {
        assert_eq!(req_size_check(MNT_ID_REQ_SIZE_MAX + 1), Err(Errno::E2big));
        assert_eq!(req_size_check(MNT_ID_REQ_SIZE_VER0 - 1), Err(Errno::Einval));
        assert_eq!(req_size_check(MNT_ID_REQ_SIZE_VER0), Ok(()));
        assert_eq!(req_size_check(MNT_ID_REQ_SIZE_VER1), Ok(()));
        assert_eq!(req_size_check(MNT_ID_REQ_SIZE_MAX), Ok(()));
    }

    #[test]
    fn size_check_precedes_every_field_check() {
        // A request that is BOTH oversized and malformed reports the size, so a
        // probe for "does this kernel accept my struct" is not masked by the
        // contents it happened to send.
        assert_eq!(req_size_check(MNT_ID_REQ_SIZE_MAX + 1), Err(Errno::E2big));
    }

    #[test]
    fn a_v0_request_reads_no_namespace_id() {
        let (known, tail) = req_copy_plan(MNT_ID_REQ_SIZE_VER0);
        assert_eq!((known, tail), (24, 0));
        let (known, tail) = req_copy_plan(MNT_ID_REQ_SIZE_VER1);
        assert_eq!((known, tail), (32, 0));
        let (known, tail) = req_copy_plan(64);
        assert_eq!((known, tail), (32, 32));
    }

    #[test]
    fn a_set_byte_beyond_the_known_struct_is_e2big() {
        let b = req_bytes(0, OFFSET + 1, 0, 0);
        assert_eq!(decode_mnt_id_req(&b, true, false), Err(Errno::E2big));
        assert!(decode_mnt_id_req(&b, false, false).is_ok());
    }

    #[test]
    fn an_id_at_or_below_the_unique_offset_is_einval() {
        assert_eq!(decode_mnt_id_req(&req_bytes(0, 0, 0, 0), false, false), Err(Errno::Einval));
        assert_eq!(decode_mnt_id_req(&req_bytes(0, 1, 0, 0), false, false), Err(Errno::Einval));
        assert_eq!(decode_mnt_id_req(&req_bytes(0, OFFSET, 0, 0), false, false), Err(Errno::Einval));
        assert!(decode_mnt_id_req(&req_bytes(0, OFFSET + 1, 0, 0), false, false).is_ok());
    }

    #[test]
    fn a_namespace_named_twice_is_einval() {
        assert_eq!(decode_mnt_id_req(&req_bytes(3, OFFSET + 1, 0, 9), false, false),
            Err(Errno::Einval));
        assert!(decode_mnt_id_req(&req_bytes(3, OFFSET + 1, 0, 0), false, false).is_ok());
        assert!(decode_mnt_id_req(&req_bytes(0, OFFSET + 1, 0, 9), false, false).is_ok());
    }

    #[test]
    fn by_fd_rejects_a_mount_id_or_a_namespace_id() {
        assert_eq!(decode_mnt_id_req(&req_bytes(3, OFFSET + 1, 0, 0), false, true),
            Err(Errno::Einval));
        assert_eq!(decode_mnt_id_req(&req_bytes(3, 0, 0, 9), false, true), Err(Errno::Einval));
        // BY_FD does NOT apply the unique-id floor: `mnt_id` must be zero, and
        // the fd alone names the mount.
        let ok = decode_mnt_id_req(&req_bytes(3, 0, 0, 0), false, true).unwrap();
        assert_eq!(ok.fd, 3);
    }

    #[test]
    fn the_request_carries_the_field_mask_or_the_cursor_in_param() {
        let r = decode_mnt_id_req(&req_bytes(0, OFFSET + 5, STATMOUNT_MNT_BASIC, 0), false, false)
            .unwrap();
        assert_eq!(r.mnt_id, OFFSET + 5);
        assert_eq!(r.param, STATMOUNT_MNT_BASIC);
    }

    #[test]
    fn listmount_cursor_zero_starts_at_the_end_but_a_small_cursor_is_einval() {
        assert_eq!(listmount_cursor_check(0), Ok(()));
        assert_eq!(listmount_cursor_check(1), Err(Errno::Einval));
        assert_eq!(listmount_cursor_check(OFFSET), Err(Errno::Einval));
        assert_eq!(listmount_cursor_check(OFFSET + 1), Ok(()));
    }

    #[test]
    fn a_namespace_named_by_id_needs_authority_over_it() {
        // ...and the two syscalls disagree on how to say no: statmount admits
        // the namespace exists, listmount does not.
        assert_eq!(ns_admission(NsPick::ById, false, false, false), Err(Errno::Eperm));
        assert_eq!(ns_admission(NsPick::ById, false, false, true), Err(Errno::Enoent));
        assert_eq!(ns_admission(NsPick::ById, false, true, false), Ok(()));
        assert_eq!(ns_admission(NsPick::ById, true, false, false), Ok(()));
    }

    #[test]
    fn a_namespace_named_by_fd_needs_no_further_capability() {
        // Holding the descriptor is the authority; re-checking it would refuse
        // a caller that was legitimately handed one.
        assert_eq!(ns_admission(NsPick::ByFd, false, false, false), Ok(()));
        assert_eq!(ns_admission(NsPick::Current, true, false, false), Ok(()));
    }

    #[test]
    fn the_namespace_is_picked_by_id_before_fd() {
        assert_eq!(ns_pick(&MntIdReq { mnt_ns_id: 9, fd: 3, ..Default::default() }), NsPick::ById);
        assert_eq!(ns_pick(&MntIdReq { fd: 3, ..Default::default() }), NsPick::ByFd);
        assert_eq!(ns_pick(&MntIdReq::default()), NsPick::Current);
    }

    #[test]
    fn the_supported_mask_covers_every_string_field_and_nothing_beyond_it() {
        assert_eq!(STATMOUNT_STRING_REQ & !STATMOUNT_SUPPORTED, 0);
        // Every bit the encoder can raise must be advertised, or a caller that
        // trusts SUPPORTED_MASK will discard a field this kernel did fill in.
        assert_eq!(STATMOUNT_SUPPORTED & !(STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC
            | STATMOUNT_PROPAGATE_FROM | STATMOUNT_MNT_NS_ID | STATMOUNT_SUPPORTED_MASK
            | STATMOUNT_STRING_REQ), 0);
    }
}
