// `bpf(2)` — syscall slot 321 (x86_64) / 280 (aarch64 generic ABI),
// per `27§R02`. Module manifest; no policy lives here.
//
//   uapi.rs     `enum bpf_cmd`, `union bpf_attr` offsets, BPF_F_* flags
//   attr.rs     attr size protocol, CHECK_ATTR, capability ladders
//               (no target gate — hosted-tested in attr/tests.rs)
//   user.rs     user-memory access for the attr + insn + key/value copies
//   prog.rs     PROG_LOAD, PROG_ATTACH/DETACH, LINK_CREATE
//   map.rs      MAP_CREATE and the element/freeze commands
//   cgattach.rs per-cgroup attach-list algebra (no target gate —
//               hosted-tested in cgattach/tests.rs)
//   cgstore.rs  binds those lists to live cgroup ids + program identity
//   devcg.rs    BPF_CGROUP_DEVICE run site for the VFS device hooks
//   ids.rs      pseudo-inode numbers for the three fd-backed objects
//
// Linux: kernel/bpf/syscall.c `__sys_bpf()` (linux-master v7.2.0-rc4).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{FileType, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

pub mod uapi;
pub mod attr;
pub mod cgattach;
pub mod cgstore;
pub mod devcg;
mod user;
mod prog;
mod map;
mod ids;

use attr::Caps;
use uapi::cmd;

const BPF_FD_MODE: u16 = 0o600;

/// Re-exported for `SO_ATTACH_BPF` in the setsockopt slot.
pub use uapi::prog_type::SOCKET_FILTER as BPF_PROG_TYPE_SOCKET_FILTER;

/// eBPF program loaded by `bpf(BPF_PROG_LOAD)`. Instruction bytes,
/// Linux program type and the `bpf_prog_alloc_id()` identity stay
/// coupled in the fd-backed inode's `i_private`.
pub struct BpfProgInode {
    pub prog_type: u32,
    pub id: u32,
    pub insns: Vec<u8>,
}

/// Build the `Arc<Inode>` for a loaded program (CharDev|0o600,
/// `i_size` = bytecode length). # C: O(1)
pub fn make_bpf_prog_inode(prog_type: u32, id: u32, insns: Vec<u8>) -> InodeRef {
    let size = insns.len() as u64;
    InodeBuilder::new(ids::INO_PROG, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .size(size)
        .private(Arc::new(BpfProgInode { prog_type, id, insns }))
        .build()
}

/// `BPF_MAP_TYPE_HASH` storage. `map_flags` is retained because
/// `map_get_sys_perms()` derives the fd's read/write mode from
/// `BPF_F_RDONLY`/`BPF_F_WRONLY` plus the frozen bit.
pub struct BpfMapInode {
    pub entries: Spinlock<BTreeMap<Vec<u8>, Vec<u8>>, TaskListClass>,
    pub max_entries: u32,
    pub key_size:    u32,
    pub value_size:  u32,
    pub map_flags:   u32,
    pub frozen:      AtomicBool,
}

/// Build the `Arc<Inode>` for a freshly created BPF map. # C: O(1)
pub fn make_bpf_map_inode(m: BpfMapInode) -> InodeRef {
    InodeBuilder::new(ids::INO_MAP, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(m))
        .build()
}

/// fd-backed BPF LSM link. Dropping the last fd reference removes the
/// registry entry.
pub struct BpfLsmLinkInode {
    id: u64,
    _hook: crate::bpf_lsm::Hook,
    _prog: InodeRef,
}

impl Drop for BpfLsmLinkInode {
    fn drop(&mut self) { crate::bpf_lsm::unregister(self.id); }
}

/// Build the `Arc<Inode>` for a BPF LSM link fd. # C: O(1)
pub fn make_bpf_lsm_link_inode(link: BpfLsmLinkInode) -> InodeRef {
    InodeBuilder::new(ids::INO_LINK, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(link))
        .build()
}

/// `sys_bpf(cmd, attr, size, attr_common, size_common)` — slot 321.
/// # C: O(1) admit; O(log N) for map ops; O(insn_cnt) for PROG_LOAD
pub fn sys_bpf(args: &SyscallArgs) -> i64 {
    match dispatch(args) { Ok(v) => v, Err(e) => -(e.as_i32() as i64) }
}

fn dispatch(args: &SyscallArgs) -> Result<i64, Errno> {
    // `SYSCALL_DEFINE5(bpf, int cmd, ...)` — the command is an `int`,
    // so the upper half of the register is not part of it.
    let mut c = args.a0 as u32;
    let a = user::fetch_attr(args.a1, args.a2 as u32)?;
    if c & cmd::COMMON_ATTRS != 0 {
        user::check_common_attr(args.a3, args.a4 as u32)?;
        c &= !cmd::COMMON_ATTRS;
    }
    let caps = caps_now()?;
    match c {
        cmd::MAP_CREATE                 => map::create(&a, caps),
        cmd::MAP_LOOKUP_ELEM            => map::elem(&a, map::MapOp::Lookup),
        cmd::MAP_UPDATE_ELEM            => map::elem(&a, map::MapOp::Update),
        cmd::MAP_DELETE_ELEM            => map::elem(&a, map::MapOp::Delete),
        cmd::MAP_LOOKUP_AND_DELETE_ELEM => map::elem(&a, map::MapOp::LookupAndDelete),
        cmd::MAP_GET_NEXT_KEY           => map::get_next_key(&a),
        cmd::MAP_FREEZE                 => map::freeze(&a),
        cmd::PROG_LOAD                  => prog::load(&a, caps),
        cmd::PROG_ATTACH                => prog::attach(&a),
        cmd::PROG_DETACH                => prog::detach(&a),
        cmd::LINK_CREATE                => prog::link_create(&a),
        // `__sys_bpf()`'s `default: err = -EINVAL`, reached only after
        // the attr size protocol above has had its say.
        _ => Err(Errno::Einval),
    }
}

/// Effective capability snapshot. `bpf_capable()` and friends fold
/// CAP_SYS_ADMIN in (include/linux/capability.h), which [`Caps`] models.
/// # C: O(1)
fn caps_now() -> Result<Caps, Errno> {
    let cur = sched::current().ok_or(Errno::Esrch)?;
    Ok(Caps {
        bpf:       cur.has_cap(sched::cap::BPF),
        sys_admin: cur.has_cap(sched::cap::SYS_ADMIN),
        net_admin: cur.has_cap(sched::cap::NET_ADMIN),
        perfmon:   cur.has_cap(sched::cap::PERFMON),
    })
}

/// Publish a bpf object on a descriptor. Linux's `bpf_map_new_fd()`,
/// `bpf_prog_new_fd()` and `bpf_link_create` all call
/// `anon_inode_getfd(..., flags | O_CLOEXEC)`, so the descriptor must
/// NOT survive `execve` (kernel/bpf/syscall.c). # C: O(fd words)
pub(super) fn install_fd(inode: InodeRef, name: &str) -> Result<i64, Errno> {
    use vfs::{File, OpenFlags};
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let dentry = vfs::dcache::d_alloc_pseudo(name, Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    // `alloc_fd_flags_below` fails only with EMFILE (RLIMIT_NOFILE),
    // matching `get_unused_fd_flags()`.
    fdt.install_limit(file, OpenFlags::O_CLOEXEC, cur.nofile_soft())
        .map(|fd| fd as i64)
        .map_err(|_| Errno::Emfile)
}
