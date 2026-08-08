// Legacy and link cgroup attachment, ordering, query, and fd resolution.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::super::attr::{self, Attr, Caps};
use super::super::uapi;
use super::super::user;
use super::super::link::cgroup_link_by_id;
use super::inode::prog_by_id;
use super::super::{
    BpfCgroupLinkInode, BpfLsmLinkInode, BpfProgInode, 
    install_fd, make_bpf_lsm_link_inode, prime_bpf_cgroup_link,
};

pub(super) struct ClassicAttach<P, T> {
    pub(super) prog: P,
    pub(super) target: T,
    pub(super) replace: Option<P>,
    pub(super) mode: cgroup::BpfAttachMode,
}

/// Resolve new program, target, optional replacement, then mode validation. # C: O(1)
pub(super) fn resolve_classic_attach<P, T>(
    flags: u32,
    prog_fd: i32,
    target_fd: i32,
    replace_fd: i32,
    mut resolve_prog: impl FnMut(i32) -> Result<P, Errno>,
    resolve_target: impl FnOnce(i32) -> Result<T, Errno>,
) -> Result<ClassicAttach<P, T>, Errno> {
    use uapi::attach_flags as f;
    let prog = resolve_prog(prog_fd)?;
    let target = resolve_target(target_fd)?;
    let replace_requested = flags & f::REPLACE != 0;
    let multi = flags & f::ALLOW_MULTI != 0;
    let replace = if replace_requested && multi {
        Some(resolve_prog(replace_fd)?)
    } else {
        None
    };
    let mode = match flags & (f::ALLOW_OVERRIDE | f::ALLOW_MULTI) {
        0 => cgroup::BpfAttachMode::Single,
        f::ALLOW_OVERRIDE => cgroup::BpfAttachMode::Override,
        f::ALLOW_MULTI => cgroup::BpfAttachMode::Multi,
        _ => return Err(Errno::Einval),
    };
    if replace_requested && !multi
        || replace_requested && flags & (f::BEFORE | f::AFTER) != 0 {
        return Err(Errno::Einval);
    }
    Ok(ClassicAttach { prog, target, replace, mode })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OrderRequest {
    Empty,
    First,
    Last,
    BeforeProg { id: bool, value: u32 },
    AfterProg { id: bool, value: u32 },
    BeforeLink { id: bool, value: u32 },
    AfterLink { id: bool, value: u32 },
}

/// Decode owner-specific cgroup ordering selection. # C: O(1)
pub(super) fn decode_order(
    flags: u32,
    relative: u32,
    link_owner: bool,
) -> Result<OrderRequest, Errno> {
    use uapi::attach_flags as f;
    let before = flags & f::BEFORE != 0;
    let after = flags & f::AFTER != 0;
    let link = flags & f::LINK != 0;
    let id = flags & f::ID != 0;
    if link || id || relative != 0 {
        if before == after || link != link_owner { return Err(Errno::Einval); }
        return Ok(match (link, before) {
            (false, true) => OrderRequest::BeforeProg { id, value: relative },
            (false, false) => OrderRequest::AfterProg { id, value: relative },
            (true, true) => OrderRequest::BeforeLink { id, value: relative },
            (true, false) => OrderRequest::AfterLink { id, value: relative },
        });
    }
    Ok(match (before, after) {
        (true, true) => OrderRequest::Empty,
        (true, false) => OrderRequest::First,
        _ => OrderRequest::Last,
    })
}

enum OwnedPosition {
    Empty,
    First,
    Last,
    BeforeProg(InodeRef),
    AfterProg(InodeRef),
    BeforeLink { id: u64, _pin: InodeRef },
    AfterLink { id: u64, _pin: InodeRef },
}

struct OwnedOrder {
    position: OwnedPosition,
    preorder: bool,
}

impl OwnedOrder {
    fn borrow(&self) -> cgroup::BpfAttachOrder<'_> {
        use cgroup::{BpfAttachAnchor as A, BpfAttachPosition as P};
        let position = match &self.position {
            OwnedPosition::Empty => P::Empty,
            OwnedPosition::First => P::First,
            OwnedPosition::Last => P::Last,
            OwnedPosition::BeforeProg(prog) => P::Before(A::Legacy(prog)),
            OwnedPosition::AfterProg(prog) => P::After(A::Legacy(prog)),
            OwnedPosition::BeforeLink { id, .. } => P::Before(A::Link(*id)),
            OwnedPosition::AfterLink { id, .. } => P::After(A::Link(*id)),
        };
        cgroup::BpfAttachOrder { position, preorder: self.preorder }
    }
}

fn resolve_order(flags: u32, relative: u32, link_owner: bool) -> Result<OwnedOrder, Errno> {
    let request = decode_order(flags, relative, link_owner)?;
    let position = match request {
        OrderRequest::Empty => OwnedPosition::Empty,
        OrderRequest::First => OwnedPosition::First,
        OrderRequest::Last => OwnedPosition::Last,
        OrderRequest::BeforeProg { id, value } => {
            OwnedPosition::BeforeProg(resolve_prog_anchor(id, value)?)
        }
        OrderRequest::AfterProg { id, value } => {
            OwnedPosition::AfterProg(resolve_prog_anchor(id, value)?)
        }
        OrderRequest::BeforeLink { id, value } => {
            let (link_id, pin) = resolve_link_anchor(id, value)?;
            OwnedPosition::BeforeLink { id: link_id, _pin: pin }
        }
        OrderRequest::AfterLink { id, value } => {
            let (link_id, pin) = resolve_link_anchor(id, value)?;
            OwnedPosition::AfterLink { id: link_id, _pin: pin }
        }
    };
    Ok(OwnedOrder {
        position,
        preorder: flags & uapi::attach_flags::PREORDER != 0,
    })
}

fn resolve_prog_anchor(id: bool, value: u32) -> Result<InodeRef, Errno> {
    if id { prog_by_id(value).ok_or(Errno::Enoent) }
    else if value == 0 { Err(Errno::Einval) }
    else { prog_inode_from_fd(value as i32) }
}

fn resolve_link_anchor(id: bool, value: u32) -> Result<(u64, InodeRef), Errno> {
    let inode = if id {
        cgroup_link_by_id(value)?
    } else if value == 0 {
        return Err(Errno::Einval);
    } else {
        inode_from_fd(value as i32)?
    };
    let link = inode.private::<BpfCgroupLinkInode>().ok_or(Errno::Einval)?;
    Ok((link.id as u64, inode))
}

fn classic_order(
    flags: u32,
    relative: u32,
    mode: cgroup::BpfAttachMode,
    direct_empty: bool,
) -> Result<OwnedOrder, Errno> {
    if !classic_order_needs_resolution(flags, mode, direct_empty) {
        Ok(OwnedOrder {
            position: OwnedPosition::Last,
            preorder: flags & uapi::attach_flags::PREORDER != 0,
        })
    } else {
        resolve_order(flags, relative, false)
    }
}

pub(super) fn classic_order_needs_resolution(
    flags: u32,
    mode: cgroup::BpfAttachMode,
    direct_empty: bool,
) -> bool {
    flags & uapi::attach_flags::REPLACE == 0
        && (mode == cgroup::BpfAttachMode::Multi || direct_empty)
}

/// Resolve target before the effective-query pointer constraint. # C: O(1)
pub(super) fn resolve_query_target<T>(
    query: &attr::ProgQuery,
    resolve_target: impl FnOnce(i32) -> Result<T, Errno>,
) -> Result<T, Errno> {
    let target = resolve_target(query.target_fd as i32)?;
    if query.query_flags & uapi::query_flags::EFFECTIVE != 0
        && query.prog_attach_flags != 0 {
        return Err(Errno::Einval);
    }
    Ok(target)
}

/// Legacy cgroup attach/detach syscall work. # C: O(descendants * programs)
pub(super) fn attach(a: &Attr, detach: bool, caps: Caps) -> Result<i64, Errno> {
    use uapi::off::prog_attach as o;
    let ptype = attr::prog_attach_check(a)?;
    let raw_attach_type = a.u32_at(o::ATTACH_TYPE);
    let attach_type = cgroup_attach_type(raw_attach_type)
        .ok_or_else(|| attr::prog_attach_verdict(ptype))?;
    let target_fd = a.u32_at(o::TARGET_FD) as i32;
    let prog_fd = a.u32_at(o::ATTACH_BPF_FD) as i32;
    let expected_revision = a.u64_at(o::EXPECTED_REVISION);
    if detach {
        if a.u32_at(o::ATTACH_FLAGS) != 0 || a.u32_at(o::RELATIVE_FD) != 0 {
            return Err(Errno::Einval);
        }
        let target = cgroup_from_fd(target_fd)?;
        let inode = prog_inode_from_fd(prog_fd).ok()
            .filter(|inode| prog_type_of(inode) == Ok(ptype));
        cgroup::bpf::detach(
            target.cgid(), attach_type, inode.as_ref(), expected_revision,
        ).map_err(super::super::cgroup_device::map_error)?;
    } else {
        let flags = a.u32_at(o::ATTACH_FLAGS);
        let prog = typed_prog_inode_from_fd(prog_fd, ptype)?;
        ensure_attach_compatible(&prog, raw_attach_type, caps, false)?;
        let resolved = resolve_classic_attach(
            flags, prog_fd, target_fd, a.u32_at(o::REPLACE_BPF_FD) as i32,
            |fd| {
                if fd == prog_fd { Ok(Arc::clone(&prog)) }
                else { typed_prog_inode_from_fd(fd, ptype) }
            },
            cgroup_from_fd,
        )?;
        cgroup::bpf::check_revision(
            resolved.target.cgid(), attach_type, expected_revision,
        ).map_err(super::super::cgroup_device::map_error)?;
        let direct_empty = cgroup::bpf::query(resolved.target.cgid(), attach_type)
            .map_err(super::super::cgroup_device::map_error)?.direct.is_empty();
        let order = classic_order(
            flags, a.u32_at(o::RELATIVE_FD), resolved.mode, direct_empty,
        )?;
        cgroup::bpf::attach(
            resolved.target.cgid(), attach_type, resolved.prog, resolved.mode,
            order.borrow(), resolved.replace.as_ref(), expected_revision,
        ).map_err(super::super::cgroup_device::map_error)?;
    }
    Ok(0)
}

/// Cgroup direct/effective program query. # C: O(program count)
pub(super) fn query(
    a: &Attr,
    uattr: u64,
    uattr_size: u32,
    caps: Caps,
) -> Result<i64, Errno> {
    use uapi::off::prog_query as o;
    let q = attr::prog_query_check(a, caps)?;
    let target = resolve_query_target(&q, cgroup_from_fd)?;
    let attach_type = cgroup_attach_type(q.attach_type).ok_or(Errno::Einval)?;
    let snapshot = cgroup::bpf::query(target.cgid(), attach_type)
        .map_err(super::super::cgroup_device::map_error)?;
    let effective = q.query_flags & uapi::query_flags::EFFECTIVE != 0;
    let programs = if effective { &snapshot.effective } else { &snapshot.direct };
    let total = programs.len() as u32;
    let attach_flags = if effective {
        0u32
    } else {
        match snapshot.mode {
            Some(cgroup::BpfAttachMode::Single) | None => 0,
            Some(cgroup::BpfAttachMode::Override) => uapi::attach_flags::ALLOW_OVERRIDE,
            Some(cgroup::BpfAttachMode::Multi) => uapi::attach_flags::ALLOW_MULTI,
        }
    };
    user::write_bytes(uattr + o::ATTACH_FLAGS as u64, &attach_flags.to_ne_bytes())?;
    user::write_bytes(uattr + o::PROG_CNT as u64, &total.to_ne_bytes())?;
    if uattr_size as usize >= o::LAST_END {
        let revision = if effective { 0 } else { snapshot.revision };
        user::write_bytes(uattr + o::REVISION as u64, &revision.to_ne_bytes())?;
    }
    if q.prog_cnt == 0 || q.prog_ids == 0 || total == 0 { return Ok(0); }
    let count = q.prog_cnt.min(total) as usize;
    let mut ids = Vec::with_capacity(count * 4);
    for inode in programs.iter().take(count) {
        let id = inode.private::<BpfProgInode>().ok_or(Errno::Einval)?.id;
        ids.extend_from_slice(&id.to_ne_bytes());
    }
    user::write_bytes(q.prog_ids, &ids)?;
    if q.prog_attach_flags != 0 {
        let mut flags = Vec::with_capacity(count * 4);
        for _ in 0..count { flags.extend_from_slice(&attach_flags.to_ne_bytes()); }
        user::write_bytes(q.prog_attach_flags, &flags)?;
    }
    if q.prog_cnt < total { Err(Errno::Enospc) } else { Ok(0) }
}

/// Recover a live queried program object. # C: O(log programs)
pub(super) fn get_fd_by_id(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let id = attr::prog_get_fd_by_id_check(a, caps)?;
    let inode = prog_by_id(id).ok_or(Errno::Enoent)?;
    install_fd(inode, "bpf-prog")
}

/// Create an LSM or owner-identified cgroup link. # C: O(descendants * programs)
pub(super) fn link_create(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let l = attr::link_create_check(a)?;
    let inode = prog_inode_from_fd(l.prog_fd as i32)?;
    ensure_attach_compatible(&inode, l.attach_type, caps, true)?;
    if let Some(attach_type) = cgroup_attach_type(l.attach_type) {
        attr::cgroup_link_flags_check(l.flags)?;
        let target = cgroup_from_fd(l.target_fd as i32)?;
        cgroup::bpf::check_revision(
            target.cgid(), attach_type, l.expected_revision,
        ).map_err(super::super::cgroup_device::map_error)?;
        let order = resolve_order(l.flags, l.relative_fd, true)?;
        let primer = prime_bpf_cgroup_link(
            target.cgid(), attach_type, Arc::clone(&inode),
        )?;
        cgroup::bpf::attach_link(
            target.cgid(), attach_type, primer.id() as u64, inode,
            order.borrow(), l.expected_revision,
        ).map_err(super::super::cgroup_device::map_error)?;
        return Ok(primer.settle());
    }
    if l.attach_type != uapi::attach_type::LSM_MAC || l.target_fd != 0 || l.flags != 0 {
        return Err(Errno::Einval);
    }
    let hook = crate::bpf_lsm::hook_from_target_btf_id(l.target_btf_id)
        .ok_or(Errno::Eopnotsupp)?;
    let id = crate::bpf_lsm::register(hook);
    let link = make_bpf_lsm_link_inode(BpfLsmLinkInode { id, _hook: hook, _prog: inode });
    install_fd(link, "bpf-link")
}

fn cgroup_attach_type(raw: u32) -> Option<cgroup::CgroupBpfAttachType> {
    use cgroup::CgroupBpfAttachType as C;
    use uapi::attach_type as a;
    Some(match raw {
        a::CGROUP_DEVICE => C::Device,
        a::CGROUP_INET_INGRESS => C::InetIngress,
        a::CGROUP_INET_EGRESS => C::InetEgress,
        a::CGROUP_INET4_BIND => C::Inet4Bind,
        a::CGROUP_INET6_BIND => C::Inet6Bind,
        a::CGROUP_INET4_CONNECT => C::Inet4Connect,
        a::CGROUP_INET6_CONNECT => C::Inet6Connect,
        _ => return None,
    })
}

pub(super) fn ensure_attach_compatible(
    inode: &InodeRef,
    attach_type: u32,
    caps: Caps,
    link_create: bool,
) -> Result<(), Errno> {
    let prog = inode.private::<BpfProgInode>().ok_or(Errno::Einval)?;
    attach_cap_check(prog.prog_type, caps, link_create)?;
    if attr::attach_type_to_prog_type(attach_type) != prog.prog_type {
        return Err(Errno::Einval);
    }
    if prog.prog_type == uapi::prog_type::CGROUP_SOCK_ADDR
        && prog.expected_attach_type != attach_type
        || prog.prog_type == uapi::prog_type::CGROUP_SKB
            && prog.enforce_expected_attach_type
            && prog.expected_attach_type != attach_type {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// `bpf_prog_attach_check_attach_type()` CGROUP_SKB token capability.
/// Legacy PROG_ATTACH collapses its verdict to EINVAL; LINK_CREATE preserves EPERM. # C: O(1)
pub(super) fn attach_cap_check(
    prog_type: u32,
    caps: Caps,
    link_create: bool,
) -> Result<(), Errno> {
    if prog_type != uapi::prog_type::CGROUP_SKB || caps.net_admin_capable() { return Ok(()); }
    Err(if link_create { Errno::Eperm } else { Errno::Einval })
}

fn inode_from_fd(fd: i32) -> Result<InodeRef, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on syscall path; fd table is pinned.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    Ok(Arc::clone(file.inode()))
}

pub(super) fn prog_inode_from_fd(fd: i32) -> Result<InodeRef, Errno> {
    let inode = inode_from_fd(fd)?;
    if inode.private::<BpfProgInode>().is_none() { return Err(Errno::Einval); }
    Ok(inode)
}

fn prog_type_of(inode: &InodeRef) -> Result<u32, Errno> {
    inode.private::<BpfProgInode>().map(|p| p.prog_type).ok_or(Errno::Einval)
}

fn typed_prog_inode_from_fd(fd: i32, ptype: u32) -> Result<InodeRef, Errno> {
    let inode = prog_inode_from_fd(fd)?;
    if prog_type_of(&inode)? != ptype { return Err(Errno::Einval); }
    Ok(inode)
}

fn cgroup_from_fd(fd: i32) -> Result<cgroup::bpf::DeviceTarget, Errno> {
    let inode = inode_from_fd(fd)?;
    if inode.file_type() != vfs::FileType::Directory { return Err(Errno::Ebadf); }
    let cgid = cgroup::cgid_from_dir_inode(&inode).ok_or(Errno::Ebadf)?;
    cgroup::bpf::device_target(cgid).map_err(super::super::cgroup_device::map_error)
}
