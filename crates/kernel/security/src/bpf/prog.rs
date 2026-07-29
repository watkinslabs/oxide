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
    let inode = make_bpf_prog_inode(p.prog_type, insns);
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
/// comes from the pair (opcode whitelist, sandboxed interpreter):
/// `verify_socket_filter` admits only the opcodes `bpf_interp`
/// implements, and `bpf_interp` addresses its 512-byte stack and the
/// read-only ctx through synthetic addresses with bounds checks, never
/// forming a raw pointer from program data. `SOCKET_FILTER` is
/// therefore the one loadable type (see `attr::prog_type_supported`);
/// a new type must arrive with both a runner and its own gate here.
///
/// The structural rejects all map onto Linux verifier paths returning
/// `-EINVAL`: `"jump out of range"`, `"last insn is not an exit or
/// jmp"`, `"R%d is invalid"`, `"unknown opcode %02x"`
/// (kernel/bpf/verifier.c). # C: O(insn_cnt)
fn verify(prog_type: u32, insns: &[u8]) -> Result<(), Errno> {
    debug_assert!(prog_type == uapi::prog_type::SOCKET_FILTER);
    crate::bpf_verify::verify_socket_filter(insns).map_err(|_| Errno::Einval)
}

/// `bpf_prog_attach()` / `bpf_prog_detach()`. # C: O(1)
pub(super) fn attach(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::prog_attach as o;
    let ptype = attr::prog_attach_check(a)?;
    // `bpf_prog_get_type(attr->attach_bpf_fd, ptype)` — a bad fd is
    // EBADF and a fd of the wrong object type is EINVAL, both ahead of
    // the attacher's own verdict.
    let inode = prog_inode_from_fd(a.u32_at(o::ATTACH_BPF_FD) as i32)?;
    if prog_type_of(&inode)? != ptype { return Err(Errno::Einval); }
    Err(attr::prog_attach_verdict(ptype))
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
