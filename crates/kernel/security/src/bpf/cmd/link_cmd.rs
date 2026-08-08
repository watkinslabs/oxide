// `BPF_LINK_GET_FD_BY_ID`, `BPF_LINK_GET_NEXT_ID`, `BPF_LINK_DETACH`,
// `BPF_LINK_UPDATE`, `BPF_ITER_CREATE`.
//
// Each command's admission ladder is a free function taking only its
// inputs, so the ordering the reference fixes — which check runs before
// which, and therefore which errno a caller that violates two rules at
// once observes — is decided here and covered by hosted tests.

extern crate alloc;

use syscall::errno::Errno;

use super::super::attr::{self, Attr, Caps};
use super::super::link::{link_by_id, next_live_link_id};
use super::super::uapi;
use super::super::{BpfCgroupLinkInode, install_fd};
use super::next_id;
use super::objfd::{self, LinkKind};

/// `bpf_link_get_fd_by_id()`. # C: O(log links + fd words)
pub(in super::super) fn get_fd_by_id(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    use uapi::off::link_get_fd_by_id as o;
    attr::check_attr(a, o::LAST_END)?;
    if !caps.sys_admin { return Err(Errno::Eperm); }
    install_fd(link_by_id(a.u32_at(o::LINK_ID))?, "bpf-link")
}

/// `BPF_LINK_GET_NEXT_ID` over the one link id registry. # C: O(live links)
pub(in super::super) fn get_next_id(a: &Attr, attr_ptr: u64, caps: Caps) -> Result<i64, Errno> {
    next_id::get_next_id(a, attr_ptr, caps, next_live_link_id)
}

/// Whether a link kind has a detach operation. A kind without one is
/// `-EOPNOTSUPP` (95) — note this is *not* the `ENOTSUPP` (524) several
/// neighbouring commands return for the same shape of refusal.
/// # C: O(1)
fn detach_verdict(kind: LinkKind) -> Result<(), Errno> {
    match kind {
        LinkKind::Cgroup => Ok(()),
        LinkKind::Lsm | LinkKind::Iter => Err(Errno::Eopnotsupp),
    }
}

/// Whether a link kind has an update operation. A kind without one is
/// `-EINVAL`, not the `EOPNOTSUPP` its detach counterpart returns.
/// # C: O(1)
fn update_verdict(kind: LinkKind) -> Result<(), Errno> {
    match kind {
        LinkKind::Cgroup => Ok(()),
        LinkKind::Lsm | LinkKind::Iter => Err(Errno::Einval),
    }
}

/// Whether a link kind is an iterator link. # C: O(1)
fn iter_verdict(kind: LinkKind) -> Result<(), Errno> {
    match kind {
        LinkKind::Iter => Ok(()),
        LinkKind::Cgroup | LinkKind::Lsm => Err(Errno::Einval),
    }
}

/// `link_detach()`. No capability: holding the descriptor is the right.
/// # C: O(descendants * effective programs)
pub(in super::super) fn detach(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::link_detach as o;
    attr::check_attr(a, o::LAST_END)?;
    let (inode, kind) = objfd::link_from_fd(a.u32_at(o::LINK_FD))?;
    detach_verdict(kind)?;
    inode.private::<BpfCgroupLinkInode>().ok_or(Errno::Einval)?.detach()
}

/// Which program descriptors `link_update()` must resolve, given its
/// flags and `old_prog_fd`. Without `BPF_F_REPLACE` a nonzero
/// `old_prog_fd` is a caller error, and it is diagnosed *after* the new
/// program's descriptor is resolved.
/// # C: O(1)
fn update_old_fd(flags: u32, old_prog_fd: u32) -> Result<Option<u32>, Errno> {
    if flags & uapi::attach_flags::REPLACE != 0 { return Ok(Some(old_prog_fd)); }
    if old_prog_fd != 0 { return Err(Errno::Einval); }
    Ok(None)
}

/// `link_update()`. A link type with no update operation is `-EINVAL`
/// (the LSM links this kernel mints have none). # C: O(descendants * programs)
pub(in super::super) fn update(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::link_update as o;
    attr::check_attr(a, o::LAST_END)?;
    let flags = a.u32_at(o::FLAGS);
    if flags & !uapi::attach_flags::REPLACE != 0 { return Err(Errno::Einval); }
    let (inode, kind) = objfd::link_from_fd(a.u32_at(o::LINK_FD))?;
    let new_prog = objfd::prog_from_fd(a.u32_at(o::NEW_PROG_FD))?;
    let old_prog = match update_old_fd(flags, a.u32_at(o::OLD_PROG_FD))? {
        Some(fd) => Some(objfd::prog_from_fd(fd)?),
        None => None,
    };
    update_verdict(kind)?;
    let link = inode.private::<BpfCgroupLinkInode>().ok_or(Errno::Einval)?;
    same_prog_type(&link.prog(), &new_prog)?;
    link.replace_prog(new_prog, old_prog.as_ref())
}

/// A link's replacement program must be the same program type as the one
/// it runs. # C: O(1)
fn same_prog_type(
    current: &vfs::InodeRef,
    replacement: &vfs::InodeRef,
) -> Result<(), Errno> {
    use super::super::BpfProgInode;
    let current = current.private::<BpfProgInode>().ok_or(Errno::Einval)?;
    let replacement = replacement.private::<BpfProgInode>().ok_or(Errno::Einval)?;
    if current.prog_type != replacement.prog_type { return Err(Errno::Einval); }
    Ok(())
}

/// `bpf_iter_create()`. The link must be an iterator link; every other
/// link type is `-EINVAL`. # C: O(fd words)
pub(in super::super) fn iter_create(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::iter_create as o;
    attr::check_attr(a, o::LAST_END)?;
    if a.u32_at(o::FLAGS) != 0 { return Err(Errno::Einval); }
    let (inode, kind) = objfd::link_from_fd(a.u32_at(o::LINK_FD))?;
    iter_verdict(kind)?;
    super::super::iter::new_fd(inode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr_at(pairs: &[(usize, u32)]) -> Attr {
        let mut a = Attr::zeroed();
        for (off, value) in pairs {
            a.bytes[*off..*off + 4].copy_from_slice(&value.to_ne_bytes());
        }
        a
    }

    #[test]
    fn link_command_check_attr_boundaries_are_the_uapi_offsetofends() {
        assert_eq!(uapi::off::link_get_fd_by_id::LAST_END, 4);
        assert_eq!(uapi::off::link_detach::LAST_END, 4);
        assert_eq!(uapi::off::link_update::LAST_END, 16);
        assert_eq!(uapi::off::iter_create::LAST_END, 8);
    }

    /// The zero-tail check runs before the capability, so a malformed
    /// unprivileged request is EINVAL rather than EPERM.
    #[test]
    fn get_fd_by_id_checks_the_attr_tail_before_cap_sys_admin() {
        let mut a = attr_at(&[(uapi::off::link_get_fd_by_id::LINK_ID, 1)]);
        a.bytes[uapi::off::link_get_fd_by_id::LAST_END] = 1;
        assert_eq!(get_fd_by_id(&a, Caps::default()), Err(Errno::Einval));
    }

    #[test]
    fn get_fd_by_id_without_cap_sys_admin_is_eperm_even_for_a_live_id() {
        let a = attr_at(&[(uapi::off::link_get_fd_by_id::LINK_ID, 1)]);
        assert_eq!(get_fd_by_id(&a, Caps::default()), Err(Errno::Eperm));
        let bpf_only = Caps { bpf: true, sys_admin: false, net_admin: true, perfmon: true };
        assert_eq!(get_fd_by_id(&a, bpf_only), Err(Errno::Eperm));
    }

    /// Link id 0 never names an object, so a privileged lookup of it is
    /// ENOENT and not EAGAIN or EINVAL.
    #[test]
    fn link_id_zero_is_enoent() {
        let admin = Caps { bpf: false, sys_admin: true, net_admin: false, perfmon: false };
        assert_eq!(get_fd_by_id(&attr_at(&[]), admin), Err(Errno::Enoent));
        assert_eq!(link_by_id(0).err(), Some(Errno::Enoent));
    }

    #[test]
    fn detach_and_iter_create_take_no_capability_and_check_their_tail() {
        let mut a = attr_at(&[(uapi::off::link_detach::LINK_FD, 0)]);
        a.bytes[uapi::off::link_detach::LAST_END] = 1;
        assert_eq!(detach(&a), Err(Errno::Einval));

        let mut a = attr_at(&[(uapi::off::iter_create::LINK_FD, 0)]);
        a.bytes[uapi::off::iter_create::LAST_END] = 1;
        assert_eq!(iter_create(&a), Err(Errno::Einval));
    }

    /// `flags` is rejected before the link descriptor is resolved, so a
    /// nonzero flag with a closed fd is EINVAL, not EBADF.
    #[test]
    fn iter_create_rejects_nonzero_flags_before_touching_the_descriptor() {
        let a = attr_at(&[
            (uapi::off::iter_create::LINK_FD, u32::MAX),
            (uapi::off::iter_create::FLAGS, 1),
        ]);
        assert_eq!(iter_create(&a), Err(Errno::Einval));
    }

    /// The three link commands refuse a kind that cannot serve them with
    /// three *different* errnos, and `ENOTSUPP` (524) is none of them.
    #[test]
    fn each_link_command_refuses_an_unsupported_kind_with_its_own_errno() {
        assert_eq!(detach_verdict(LinkKind::Cgroup), Ok(()));
        assert_eq!(detach_verdict(LinkKind::Lsm), Err(Errno::Eopnotsupp));
        assert_eq!(update_verdict(LinkKind::Cgroup), Ok(()));
        assert_eq!(update_verdict(LinkKind::Lsm), Err(Errno::Einval));
        assert_eq!(detach_verdict(LinkKind::Iter), Err(Errno::Eopnotsupp));
        assert_eq!(update_verdict(LinkKind::Iter), Err(Errno::Einval));
        assert_eq!(iter_verdict(LinkKind::Cgroup), Err(Errno::Einval));
        assert_eq!(iter_verdict(LinkKind::Lsm), Err(Errno::Einval));
        // The one kind that IS an iterator link; without it the three
        // ladders above would all be vacuously "no kind serves this".
        assert_eq!(iter_verdict(LinkKind::Iter), Ok(()));
        assert_eq!(Errno::Eopnotsupp.as_i32(), 95);
        assert_eq!(Errno::Enotsupp.as_i32(), 524);
    }

    #[test]
    fn link_update_accepts_only_the_replace_flag() {
        let bad = attr_at(&[
            (uapi::off::link_update::LINK_FD, u32::MAX),
            (uapi::off::link_update::FLAGS, uapi::attach_flags::REPLACE | 1),
        ]);
        assert_eq!(update(&bad), Err(Errno::Einval));
    }

    /// Without `BPF_F_REPLACE` a nonzero `old_prog_fd` is a caller error;
    /// with it, that descriptor is the one to resolve.
    #[test]
    fn old_prog_fd_is_only_meaningful_under_the_replace_flag() {
        assert_eq!(update_old_fd(0, 0), Ok(None));
        assert_eq!(update_old_fd(0, 7), Err(Errno::Einval));
        assert_eq!(update_old_fd(uapi::attach_flags::REPLACE, 0), Ok(Some(0)));
        assert_eq!(update_old_fd(uapi::attach_flags::REPLACE, 7), Ok(Some(7)));
    }
}
