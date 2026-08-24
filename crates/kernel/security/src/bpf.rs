// `bpf(2)` — syscall slot 321 (x86_64) / 280 (aarch64 generic ABI),
// per `27§5`. Module manifest; no policy lives here.
//
//   uapi.rs      `enum bpf_cmd`, `union bpf_attr` offsets, BPF_F_* flags
//   attr.rs      attr size protocol, CHECK_ATTR, capability ladders
//                (no target gate — hosted-tested in attr/tests.rs)
//   user.rs      user-memory access for the attr + insn + key/value copies
//   dispatch.rs  the command table and the per-call capability snapshot
//   cmd/         one module per command whose object is not a prog/map/btf:
//                test_run, next_id, links, stats, batch, and the ladders
//                whose backing subsystem this kernel does not have
//   prog.rs      PROG_LOAD, PROG_ATTACH/DETACH, LINK_CREATE, program object
//   map.rs       MAP_CREATE, the element/freeze commands, map object
//   link.rs      cgroup and LSM link objects and the link id registry
//   iter.rs      iterator targets, the iterator link, and its walk descriptor
//   fd.rs        descriptor publication for every fd-backed object
//   sk_filter.rs socket-filter `__sk_buff` context build and run entry
//   ids.rs       pseudo-inode numbers for fd-backed objects

extern crate alloc;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{FileType, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

pub mod uapi;
pub mod attr;
mod user;
mod dispatch;
// Directory `bpf/cmd/`; the module is `command` because `cmd` names the
// UAPI command-number module this file already imports.
#[path = "bpf/cmd.rs"]
mod command;
mod prog;
mod iter;
mod cgroup_device;
mod cgroup_network;
mod btf;
mod log;
mod link;
mod fd;
pub mod sk_filter;
pub mod sk_reuseport;
pub mod map;
mod ids;
mod token;
mod mount;
mod object;

use uapi::cmd;

pub(super) const BPF_FD_MODE: u16 = 0o600;

/// What `BPF_TASK_FD_QUERY` needs from the perf subsystem, which sits above
/// this crate: `perf_get_event()` and `event->prog`. Both arrive from the
/// syscall shim rather than this crate keeping a second copy of perf's state.
#[derive(Clone, Copy)]
pub struct PerfHooks {
    /// `perf_get_event()`: whether an inode is a perf-event fd.
    pub is_perf: fn(&InodeRef) -> bool,
    /// `event->prog`: the program attached to that event, if any.
    pub attached_prog: fn(&InodeRef) -> Option<InodeRef>,
}

pub use prog::inode::{
    BpfProgInode, ProgFacts, prog_facts, make_bpf_prog_inode, make_bpf_prog_inode_with_meta,
    make_bpf_prog_inode_with_contract, make_bpf_prog_inode_with_attach_target,
    NO_ATTACH_TARGET,
};
pub use map::inode::{BpfMapInode, make_bpf_map_inode};
pub use link::{
    BpfCgroupLinkInode, BpfLsmLinkInode, BpfRawTracepointLinkInode,
    RawTracepointHooks, RawTracepointLinkInfo, raw_tracepoint_link_info,
    make_bpf_cgroup_link_inode, make_bpf_lsm_link_inode,
};
pub use iter::{BpfIterLinkInode, IterTarget, make_bpf_iter_link_inode};
/// Width of one iterator context slot. # C: O(1)
pub const ITER_SLOT_BYTES: usize = iter::targets::SLOT_BYTES;
/// Bytes of context an iterator program addresses. # C: O(1)
pub fn iter_context_bytes() -> usize { iter::targets::CONTEXT_BYTES }
pub(crate) use link::{prime_bpf_cgroup_link, prime_bpf_raw_tracepoint_link};
#[cfg(test)]
pub(crate) use link::prime_bpf_raw_tracepoint_link_with;
pub(crate) use fd::{install_fd, install_fd_access};
pub(crate) use btf::{StreamKfunc, stream_kfunc_by_btf_id};
#[cfg(test)]
pub(crate) use btf::stream_vprintk_btf_id;

/// `bpf_prog_get(ufd)`: the program one descriptor holds, together with the
/// facts an attach site decides on. An empty descriptor is `-EBADF`; one
/// holding anything that is not a loaded program is `-EINVAL`. The caller
/// holds the returned reference for as long as it keeps the attachment, which
/// is what keeps the program alive after its own descriptor is closed.
/// # C: O(insn count)
pub fn prog_get(fd: u32) -> Result<(InodeRef, ProgFacts), Errno> {
    let inode = command::objfd::prog_from_fd(fd)?;
    let facts = prog_facts(&inode).ok_or(Errno::Einval)?;
    Ok((inode, facts))
}


/// Map value storage is separately locked so a helper can pin a value
/// without holding the map's directory lock while the interpreter runs.
pub(crate) use map::BpfMapValue;

/// Re-exported for `SO_ATTACH_BPF` in the setsockopt slot.
pub use uapi::prog_type::SOCKET_FILTER as BPF_PROG_TYPE_SOCKET_FILTER;
pub use uapi::prog_type::SK_REUSEPORT as BPF_PROG_TYPE_SK_REUSEPORT;
/// Re-exported for `PERF_EVENT_IOC_SET_BPF`, whose non-tracing arm runs only
/// this program type.
pub use uapi::prog_type::PERF_EVENT as BPF_PROG_TYPE_PERF_EVENT;
pub use cgroup_device::{
    DEVCG_ACC_MKNOD, DEVCG_ACC_READ, DEVCG_ACC_WRITE, DEVCG_DEV_BLOCK, DEVCG_DEV_CHAR,
    check as check_device_access,
};
pub(crate) use cgroup_device::inode_permission as cgroup_device_inode_permission;
pub use cgroup_network::{
    CgroupSkbAttach, CgroupSkbContext, CgroupSkbVerdict, CgroupSockAddrAttach,
    CgroupSockAddrContext, CgroupSockAddrError, CgroupSockAddrVerdict,
    run_cgroup_skb, run_cgroup_sock_addr,
};

/// Byte length of the type information this kernel publishes about itself;
/// the size a binary attribute serving those bytes reports.
/// # C: O(1) after first call
pub fn kernel_btf_len() -> u64 { btf::published_len() }

/// Windowed read of the type information this kernel publishes about
/// itself: copy from `off` into `buf`, answering the byte count and 0 at
/// end of object. A loader reads this to discover the type id naming the
/// hook stub it means to attach to, and the ids it sees are the ids the
/// load path resolves because both read one object.
/// # C: O(n)
pub fn kernel_btf_read(off: u64, buf: &mut [u8]) -> usize { btf::published_read(off, buf) }

/// Delegation token derived from a bpffs superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfTokenInode {
    pub source_magic: u64,
    pub flags: u32,
    pub allowed_cmds: u64,
    pub allowed_maps: u64,
    pub allowed_progs: u64,
    pub allowed_attachs: u64,
}

pub(crate) const BPF_FS_MAGIC: u64 = 0xcafe4a11;
pub use mount::{BpfDelegation, parse_mount_delegation};

/// Build the `Arc<Inode>` for a bpffs delegation token. # C: O(1)
pub fn make_bpf_token_inode(token: BpfTokenInode) -> InodeRef {
    InodeBuilder::new(ids::INO_TOKEN, mk_mode(FileType::Regular, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(token))
        .build()
}

/// `sys_bpf(cmd, attr, size, attr_common, size_common)` — slot 321.
/// `perf` carries the two perf-subsystem answers `BPF_TASK_FD_QUERY` needs;
/// only that command consults them.
/// # C: O(1) admit; O(log N) for map ops; O(insn_cnt) for PROG_LOAD
pub fn sys_bpf(args: &SyscallArgs, perf: PerfHooks, raw_tracepoint: RawTracepointHooks) -> i64 {
    match dispatch::dispatch(args, perf, raw_tracepoint) {
        Ok(v) => v, Err(e) => -(e.as_i32() as i64),
    }
}

/// Execute one raw-tracepoint program against the site's register-wide
/// argument vector. The attachment cookie is per link, so the same program
/// attached twice observes the cookie of the link currently invoking it.
/// # C: O(program instructions)
pub fn run_raw_tracepoint(prog: &InodeRef, args: &[u64], cookie: u64) {
    const MAX_RAW_ARGS: usize = 12;
    let Some(prog) = prog.private::<BpfProgInode>() else { return; };
    let mut context = [0u8; MAX_RAW_ARGS * core::mem::size_of::<u64>()];
    for (slot, value) in args.iter().take(MAX_RAW_ARGS).enumerate() {
        let at = slot * core::mem::size_of::<u64>();
        context[at..at + core::mem::size_of::<u64>()].copy_from_slice(&value.to_ne_bytes());
    }
    let mut state = crate::bpf_interp::HelperState { attach_cookie: cookie, ..Default::default() };
    let _ = crate::bpf_interp::run_program_with_state(&prog, &context, &[], &[], &mut state);
}

/// Decode the `BPF_OBJ_PIN` pathname after the common attribute protocol.
/// The syscall shim resolves this address through the caller's mount namespace.
/// # C: O(sizeof(bpf_attr))
pub fn obj_pin_path(args: &SyscallArgs) -> Result<u64, Errno> {
    let attr = dispatch::object_attr(args)?;
    attr::check_attr(&attr, uapi::off::obj_pin::LAST_END)?;
    Ok(attr.u64_at(uapi::off::obj_pin::PATHNAME))
}

/// Decode the `BPF_OBJ_GET` pathname after the common attribute protocol.
/// # C: O(sizeof(bpf_attr))
pub fn obj_get_path(args: &SyscallArgs) -> Result<u64, Errno> {
    let attr = dispatch::object_attr(args)?;
    attr::check_attr(&attr, uapi::off::obj_get::LAST_END)?;
    Ok(attr.u64_at(uapi::off::obj_get::PATHNAME))
}

/// Whether this command must be pathname-resolved by the syscall shim.
/// # C: O(1)
pub fn object_path_command(args: &SyscallArgs) -> Option<u32> {
    let c = (args.a0 as u32) & !cmd::COMMON_ATTRS;
    matches!(c, cmd::OBJ_PIN | cmd::OBJ_GET).then_some(c)
}

/// Publish an fd-backed BPF object under an already-resolved bpffs parent.
/// # C: O(log directory entries)
pub fn obj_pin(args: &SyscallArgs, parent: &vfs::VfsPath, name: &str) -> Result<i64, Errno> {
    object::pin(&dispatch::object_attr(args)?, parent, name, dispatch::caps_now()?)
}

/// Recover an fd for an already-resolved bpffs object.
/// # C: O(fd words)
pub fn obj_get(args: &SyscallArgs, object: &vfs::VfsPath) -> Result<i64, Errno> {
    object::get(&dispatch::object_attr(args)?, object, dispatch::caps_now()?)
}
