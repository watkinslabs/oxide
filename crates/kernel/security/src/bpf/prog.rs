// `BPF_PROG_LOAD`, `BPF_PROG_ATTACH`/`BPF_PROG_DETACH`, `BPF_LINK_CREATE`.
// Ordering mirrors kernel/bpf/syscall.c `bpf_prog_load()`,
// `bpf_prog_attach()` and `link_create()`; every errno decision itself
// lives in `attr.rs` so it is hosted-testable.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::attr::{self, Attr, Caps};
use super::cgattach::{Anchor, AttachReq};
use super::cgstore::{self, ProgRef};
use super::uapi;
use super::user;
use super::{BpfLsmLinkInode, BpfProgInode, install_fd, make_bpf_lsm_link_inode, make_bpf_prog_inode};

/// `char license[128]` in `bpf_prog_load()`.
const LICENSE_MAX: usize = 128;

/// `bpf_prog_load()`. # C: O(insn_cnt)
pub(super) fn load(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let p = attr::prog_load_check(a, caps, attr::unpriv_bpf_disabled())?;
    let total = p.insn_cnt as usize * uapi::INSN_SIZE as usize;
    // Linux copies insns then the license *before* `find_prog_type()`,
    // so a bad pointer is EFAULT even for a prog type with no runner.
    let insns = user::read_vec(p.insns, total)?;
    read_license(p.license)?;
    if !attr::prog_type_supported(p.prog_type) { return Err(Errno::Einval); }
    verify(p.prog_type, &insns)?;
    let inode = make_bpf_prog_inode(p.prog_type, cgstore::alloc_prog_id(), insns);
    install_fd(inode, "bpf-prog")
}

/// `strncpy_from_bpfptr(license, attr->license, sizeof(license) - 1) < 0`
/// is `-EFAULT` — a NULL or unmapped `attr.license` fails the load, so
/// the pointer is read one byte at a time up to the NUL. # C: O(len)
fn read_license(ptr: u64) -> Result<Vec<u8>, Errno> {
    let mut out: Vec<u8> = Vec::new();
    for i in 0..LICENSE_MAX as u64 - 1 {
        let mut b = [0u8; 1];
        user::read_bytes(ptr + i, &mut b)?;
        if b[0] == 0 { return Ok(out); }
        out.push(b[0]);
    }
    Ok(out)
}

/// `bpf_check()`. There is no path-sensitive verifier here; safety
/// comes from the pair (opcode whitelist, sandboxed interpreter): the
/// per-type entry points admit only the opcodes `bpf_interp`
/// implements, and `bpf_interp` addresses its 512-byte stack and the
/// read-only ctx through synthetic addresses with bounds checks, never
/// forming a raw pointer from program data. A new loadable type must
/// arrive with a runner, its own gate here, and its own run site.
///
/// The structural rejects all map onto Linux verifier paths returning
/// `-EINVAL`: `"jump out of range"`, `"last insn is not an exit or
/// jmp"`, `"R%d is invalid"`, `"unknown opcode %02x"`
/// (kernel/bpf/verifier.c). # C: O(insn_cnt)
fn verify(prog_type: u32, insns: &[u8]) -> Result<(), Errno> {
    let r = match prog_type {
        uapi::prog_type::CGROUP_DEVICE => crate::bpf_verify::verify_cgroup_device(insns),
        _ => crate::bpf_verify::verify_socket_filter(insns),
    };
    r.map_err(|_| Errno::Einval)
}

/// `bpf_prog_attach()`. Ordering: the attr ladder in `attr.rs`, then
/// `bpf_prog_get_type(attach_bpf_fd)` (EBADF for a non-fd, EINVAL for a
/// non-program), then `bpf_prog_attach_check_attach_type()`, then the
/// cgroup attacher — which resolves `target_fd` (EBADF unless it names a
/// cgroup directory), then `replace_bpf_fd` under `MULTI|REPLACE`.
/// # C: O(depth · progs)
pub(super) fn attach(a: &Attr) -> Result<i64, Errno> {
    use uapi::attach_flags as af;
    let p = attr::prog_attach_check(a)?;
    let inode = prog_inode_from_fd(p.attach_bpf_fd as i32)?;
    if prog_type_of(&inode)? != p.ptype { return Err(Errno::Einval); }
    attr::attach_type_matches_prog(p.ptype, p.attach_type)?;
    let cgid = cgroup_id_from_fd(p.target_fd as i32)?;
    let replace = if p.attach_flags & af::ALLOW_MULTI != 0 && p.attach_flags & af::REPLACE != 0 {
        let r = prog_inode_from_fd(p.replace_bpf_fd as i32)?;
        if prog_type_of(&r)? != p.ptype { return Err(Errno::Einval); }
        Some(ProgRef(r))
    } else { None };
    let id = prog_id_of(&inode)?;
    let anchor = resolve_anchor(p.attach_flags, p.relative_fd, p.ptype);
    let req = AttachReq {
        prog: ProgRef(inode), id, replace, flags: p.attach_flags,
        id_or_fd: p.relative_fd, revision: p.expected_revision,
    };
    cgstore::device_attach(cgid, req, anchor)?;
    Ok(0)
}

/// `bpf_prog_detach()`. A program fd that will not resolve is not fatal
/// — Linux passes `prog = NULL`, which single-attach cgroups accept.
/// # C: O(progs)
pub(super) fn detach(a: &Attr) -> Result<i64, Errno> {
    let p = attr::prog_detach_check(a)?;
    let cgid = cgroup_id_from_fd(p.target_fd as i32)?;
    let prog = prog_inode_from_fd(p.attach_bpf_fd as i32).ok()
        .filter(|i| prog_type_of(i) == Ok(p.ptype))
        .map(ProgRef);
    cgstore::device_detach(cgid, prog.as_ref(), p.expected_revision)?;
    Ok(0)
}

/// `bpf_get_anchor_prog()` / `bpf_get_anchor_link()`, deferred: the
/// errno rides in the [`Anchor`] so it surfaces where `get_prog_list()`
/// would raise it. A `BPF_F_LINK` anchor is rejected by the algebra
/// before any lookup, so no link is resolved here. # C: O(fd)
fn resolve_anchor(flags: u32, relative_fd: u32, ptype: u32) -> Anchor<ProgRef> {
    use uapi::attach_flags as af;
    if flags & af::ID != 0 { return Anchor::Id(relative_fd); }
    if flags & af::LINK != 0 || relative_fd == 0 { return Anchor::None; }
    match prog_inode_from_fd(relative_fd as i32) {
        Ok(i) if prog_type_of(&i) == Ok(ptype) => Anchor::Prog(ProgRef(i)),
        Ok(_) => Anchor::Unresolved(Errno::Einval),
        Err(e) => Anchor::Unresolved(e),
    }
}

/// `cgroup_get_from_fd()` — the fd must name a cgroup2 DIRECTORY;
/// anything else is EBADF (`css_tryget_online_from_dir`). # C: O(1)
fn cgroup_id_from_fd(fd: i32) -> Result<u64, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    file.inode().private::<cgroup::inode::CgDirData>().map(|d| d.cgid).ok_or(Errno::Ebadf)
}

/// `link_create()` for `BPF_LSM_MAC`. # C: O(1)
pub(super) fn link_create(a: &Attr) -> Result<i64, Errno> {
    let l = attr::link_create_check(a)?;
    let hook = crate::bpf_lsm::hook_from_target_btf_id(l.target_btf_id).ok_or(Errno::Eopnotsupp)?;
    let inode = prog_inode_from_fd(l.prog_fd as i32)?;
    if prog_type_of(&inode)? != uapi::prog_type::LSM { return Err(Errno::Einval); }
    let id = crate::bpf_lsm::register(hook);
    let link: InodeRef = make_bpf_lsm_link_inode(BpfLsmLinkInode { id, _hook: hook, _prog: inode });
    install_fd(link, "bpf-link")
}

fn prog_inode_from_fd(fd: i32) -> Result<InodeRef, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    let inode = Arc::clone(file.inode());
    if inode.private::<BpfProgInode>().is_none() { return Err(Errno::Einval); }
    Ok(inode)
}

fn prog_type_of(inode: &InodeRef) -> Result<u32, Errno> {
    inode.private::<BpfProgInode>().map(|p| p.prog_type).ok_or(Errno::Einval)
}

fn prog_id_of(inode: &InodeRef) -> Result<u32, Errno> {
    inode.private::<BpfProgInode>().map(|p| p.id).ok_or(Errno::Einval)
}
