// Real bpf(2) substrate per `27§R02`.
//
// Admits BPF_PROG_LOAD (cBPF — 32-bit classic-BPF instructions
// stored in a BpfProgInode) and BPF_MAP_CREATE (byte-keyed hash map
// stored in a BpfMapInode). All ops require CAP_BPF. eBPF + verifier
// + JIT are follow-ups (K10 batch in kernel-audit.md).


extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{FileType, Ino, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

mod map;
mod ids;

use map::{MapOp, handle_map_create, handle_map_freeze, handle_map_get_next_key, handle_map_op};

const BPF_FD_MODE: u16 = 0o600;

/// eBPF program loaded by `bpf(BPF_PROG_LOAD)`. Instruction bytes
/// and Linux program type remain coupled in the fd-backed inode. Lives in the inode's
/// `i_private`; built into an `InodeRef` by [`make_bpf_prog_inode`].
pub struct BpfProgInode {
    pub prog_type: u32,
    pub insns: Vec<u8>,
}

/// Build the `Arc<Inode>` for a loaded cBPF program (CharDev|0o600,
/// `i_size` = bytecode length, ops are the generic defaults). # C: O(1)
pub fn make_bpf_prog_inode(prog_type: u32, insns: Vec<u8>) -> InodeRef {
    let size = insns.len() as u64;
    InodeBuilder::new(ids::INO_PROG, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .size(size)
        .private(Arc::new(BpfProgInode { prog_type, insns }))
        .build()
}

/// Byte-keyed hash map. Linux's BPF_MAP_TYPE_HASH shape; v1 supports
/// look-up + update + delete + get_next_key via `bpf(2)` ops. Lives in
/// the inode's `i_private`.
pub struct BpfMapInode {
    pub entries: Spinlock<BTreeMap<Vec<u8>, Vec<u8>>, TaskListClass>,
    pub max_entries: u32,
    pub key_size:    u32,
    pub value_size:  u32,
    pub frozen:      AtomicBool,
}

/// Build the `Arc<Inode>` for a freshly created BPF map (CharDev|0o600).
/// # C: O(1)
pub fn make_bpf_map_inode(map: BpfMapInode) -> InodeRef {
    InodeBuilder::new(ids::INO_MAP, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(map))
        .build()
}

/// fd-backed BPF LSM link. The link keeps the program inode alive and removes
/// its registry entry when the last fd reference (the `i_private` `Arc`) is
/// dropped.
pub struct BpfLsmLinkInode {
    id: u64,
    _hook: crate::bpf_lsm::Hook,
    _prog: InodeRef,
}

impl Drop for BpfLsmLinkInode {
    fn drop(&mut self) {
        crate::bpf_lsm::unregister(self.id);
    }
}

/// Build the `Arc<Inode>` for a BPF LSM link fd (CharDev|0o600). The
/// `link` data's `Drop` unregisters the hook on last-fd close. # C: O(1)
pub fn make_bpf_lsm_link_inode(link: BpfLsmLinkInode) -> InodeRef {
    InodeBuilder::new(ids::INO_LINK, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(link))
        .build()
}

const BPF_MAP_CREATE:    u64 = 0;
const BPF_PROG_LOAD:     u64 = 5;
const BPF_MAP_LOOKUP_ELEM: u64 = 1;
const BPF_MAP_UPDATE_ELEM: u64 = 2;
const BPF_MAP_DELETE_ELEM: u64 = 3;
const BPF_MAP_GET_NEXT_KEY: u64 = 4;
const BPF_PROG_ATTACH: u64 = 8;
const BPF_PROG_DETACH: u64 = 9;
const BPF_MAP_FREEZE: u64 = 22;
const BPF_LINK_CREATE: u64 = 28;

pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
const BPF_PROG_TYPE_LSM: u32 = 29;
const BPF_LSM_MAC: u32 = 27;

/// `sys_bpf(cmd, attr, size)` — slot 321.
/// # C: O(1) for admit; O(log N) for map ops
pub fn sys_bpf(args: &SyscallArgs) -> i64 {
    let cmd = args.a0;
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::BPF) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    match cmd {
        BPF_MAP_CREATE => handle_map_create(args.a1, args.a2),
        BPF_PROG_LOAD => handle_prog_load(args.a1, args.a2),
        BPF_MAP_LOOKUP_ELEM => handle_map_op(args.a1, args.a2, MapOp::Lookup),
        BPF_MAP_UPDATE_ELEM => handle_map_op(args.a1, args.a2, MapOp::Update),
        BPF_MAP_DELETE_ELEM => handle_map_op(args.a1, args.a2, MapOp::Delete),
        BPF_MAP_GET_NEXT_KEY => handle_map_get_next_key(args.a1, args.a2),
        BPF_MAP_FREEZE => handle_map_freeze(args.a1, args.a2),
        BPF_PROG_ATTACH | BPF_PROG_DETACH => handle_prog_attach(args.a1, args.a2),
        BPF_LINK_CREATE => handle_link_create(args.a1, args.a2),
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// `bpf_attr` PROG_ATTACH/DETACH prefix:
/// { u32 target_fd; u32 attach_bpf_fd; u32 attach_type; u32 attach_flags }.
/// The verifier/enforcer for cgroup device programs is not present yet, but
/// Linux userspace expects a valid cgroup-device attach request to be accepted
/// once `BPF_PROG_LOAD` succeeded. Store/enforce is a later security layer;
/// this syscall surface must not reject systemd's device policy setup.
const BPF_ATTR_PROG_ATTACH_SIZE: u64 = 16;

fn handle_prog_attach(attr_ptr: u64, attr_size: u64) -> i64 {
    use hal::USER_VA_END;
    if attr_ptr == 0 || attr_size < BPF_ATTR_PROG_ATTACH_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr_ptr.checked_add(BPF_ATTR_PROG_ATTACH_SIZE).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: attr range validated; read the Linux attach prefix to reject
    // obviously malformed requests while accepting supported no-op attaches.
    let (target_fd, prog_fd) = unsafe {
        (
            core::ptr::read_volatile(attr_ptr as *const u32),
            core::ptr::read_volatile((attr_ptr + 4) as *const u32),
        )
    };
    if target_fd == u32::MAX || prog_fd == u32::MAX {
        return -(Errno::Ebadf.as_i32() as i64);
    }
    0
}

/// `bpf_attr` LINK_CREATE prefix:
/// { u32 prog_fd; u32 target_fd; u32 attach_type; u32 flags;
///   u32 target_btf_id }.
const BPF_ATTR_LINK_CREATE_SIZE: u64 = 20;

fn handle_link_create(attr_ptr: u64, attr_size: u64) -> i64 {
    use hal::USER_VA_END;
    if attr_ptr == 0 || attr_size < BPF_ATTR_LINK_CREATE_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr_ptr.checked_add(BPF_ATTR_LINK_CREATE_SIZE).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: attr range validated for the fixed LINK_CREATE prefix.
    let (prog_fd, target_fd, attach_type, flags, target_btf_id) = unsafe {
        (
            core::ptr::read_volatile(attr_ptr as *const u32),
            core::ptr::read_volatile((attr_ptr + 4) as *const u32),
            core::ptr::read_volatile((attr_ptr + 8) as *const u32),
            core::ptr::read_volatile((attr_ptr + 12) as *const u32),
            core::ptr::read_volatile((attr_ptr + 16) as *const u32),
        )
    };
    if attach_type != BPF_LSM_MAC || flags != 0 || target_fd != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let hook = match crate::bpf_lsm::hook_from_target_btf_id(target_btf_id) {
        Some(h) => h,
        None => return -(Errno::Eopnotsupp.as_i32() as i64),
    };
    let prog_inode = match bpf_prog_inode_from_fd(prog_fd as i32) {
        Some(i) => i,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let prog = match prog_inode.private::<BpfProgInode>() {
        Some(p) => p,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    if prog.prog_type != BPF_PROG_TYPE_LSM {
        return -(Errno::Einval.as_i32() as i64);
    }

    let id = crate::bpf_lsm::register(hook);
    let inode: InodeRef = make_bpf_lsm_link_inode(BpfLsmLinkInode {
        id,
        _hook: hook,
        _prog: prog_inode,
    });
    install_fd(inode, "bpf-link")
}

fn bpf_prog_inode_from_fd(fd: i32) -> Option<InodeRef> {
    let cur = sched::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let file = fdt.get(fd).ok()?;
    let inode = Arc::clone(file.inode());
    if inode.private::<BpfProgInode>().is_some() {
        Some(inode)
    } else {
        None
    }
}

/// Maximum instruction count we accept on PROG_LOAD. Linux's
/// classic ceiling is 4096 (`BPF_MAXINSNS`); we mirror that.
/// Each insn is 8 bytes, so the max copy is 32 KiB.
const BPF_MAXINSNS: u32 = 4096;
const BPF_INSN_SIZE: u32 = 8;

/// Decode the `bpf_attr` PROG_LOAD variant, copy the insn array
/// out of userspace, stash it in a fresh BpfProgInode, install
/// the fd. Pre-F102 this stored an empty Vec; now real cBPF/eBPF
/// bytecode survives PROG_LOAD → fd retrieval and is available
/// for the verifier (K10 follow-up).
/// # C: O(insn_cnt) memcpy
fn handle_prog_load(attr_ptr: u64, attr_size: u64) -> i64 {
    use hal::USER_VA_END;
    // The smallest useful prog_load attr is 16 bytes (prog_type +
    // insn_cnt + insns u64). Linux accepts shorter attrs by zero-
    // filling missing fields; we mirror that with a minimum of 24
    // (also reading the license ptr so we can fail-fast on the
    // legacy "GPL" requirement once enforcement lands).
    if attr_ptr == 0 || attr_size < 16 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr_ptr.checked_add(24).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: attr_ptr+24 validated < USER_VA_END; user page mapped under caller's AS; 24-byte bounded read on the syscall path.
    let (prog_type, insn_cnt, insns_ptr) = unsafe {
        let pt  = core::ptr::read_volatile(attr_ptr as *const u32);
        let cnt = core::ptr::read_volatile((attr_ptr + 4) as *const u32);
        let ip  = core::ptr::read_volatile((attr_ptr + 8) as *const u64);
        (pt, cnt, ip)
    };
    if insn_cnt == 0 || insn_cnt > BPF_MAXINSNS {
        return -(Errno::Einval.as_i32() as i64);
    }
    let total = (insn_cnt as u64) * (BPF_INSN_SIZE as u64);
    if insns_ptr == 0 || insns_ptr >= USER_VA_END
        || insns_ptr.checked_add(total).map_or(true, |e| e > USER_VA_END)
    {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mut insns: Vec<u8> = alloc::vec![0u8; total as usize];
    for i in 0..total {
        // SAFETY: insns_ptr..insns_ptr+total validated < USER_VA_END above; per-byte volatile read through caller's CR3.
        insns[i as usize] = unsafe {
            core::ptr::read_volatile((insns_ptr + i) as *const u8)
        };
    }
    // F107: structural verifier. Reject malformed programs before
    // any future JIT or interpreter touches them.
    let verified = if prog_type == BPF_PROG_TYPE_SOCKET_FILTER {
        crate::bpf_verify::verify_socket_filter(&insns)
    } else {
        crate::bpf_verify::verify(&insns)
    };
    if verified.is_err() {
        return -(Errno::Einval.as_i32() as i64);
    }
    let inode: InodeRef = make_bpf_prog_inode(prog_type, insns);
    install_fd(inode, "bpf-prog")
}

pub(super) fn install_fd(inode: InodeRef, name: &str) -> i64 {
    use alloc::sync::Arc;
    use vfs::{File, OpenFlags};
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = vfs::dcache::d_alloc_pseudo(name, Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    match fdt.alloc_limit(file, cur.nofile_soft()) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}
