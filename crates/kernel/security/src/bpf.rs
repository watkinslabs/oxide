// `bpf(2)` — syscall slot 321 (x86_64) / 280 (aarch64 generic ABI),
// per `27§R02`. Module manifest; no policy lives here.
//
//   uapi.rs  `enum bpf_cmd`, `union bpf_attr` offsets, BPF_F_* flags
//   attr.rs  attr size protocol, CHECK_ATTR, capability ladders
//            (no target gate — hosted-tested in attr/tests.rs)
//   user.rs  user-memory access for the attr + insn + key/value copies
//   prog.rs  PROG_LOAD, PROG_ATTACH/DETACH, LINK_CREATE
//   map.rs   MAP_CREATE and the element/freeze commands
//   ids.rs   pseudo-inode numbers for fd-backed objects

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{FileType, InodeRef, InodeBuilder, default_inode_ops, default_file_ops, mk_mode};

pub mod uapi;
pub mod attr;
mod user;
mod prog;
mod cgroup_device;
mod cgroup_network;
mod btf;
mod log;
pub(crate) mod map;
mod ids;
mod token;

use attr::Caps;
use uapi::cmd;

pub(super) const BPF_FD_MODE: u16 = 0o600;

/// Re-exported for `SO_ATTACH_BPF` in the setsockopt slot.
pub use uapi::prog_type::SOCKET_FILTER as BPF_PROG_TYPE_SOCKET_FILTER;
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

/// eBPF program loaded by `bpf(BPF_PROG_LOAD)`. Instruction bytes and
/// Linux program type stay coupled in the fd-backed inode's `i_private`.
pub struct BpfProgInode {
    pub id: u32,
    pub prog_type: u32,
    pub expected_attach_type: u32,
    /// Linux sets this only when verifier return-range analysis makes the
    /// expected CGROUP_SKB direction part of the program's attach contract.
    pub enforce_expected_attach_type: bool,
    pub insns: Vec<u8>,
    /// Canonical program-owned map set. Relocation maps retain index order;
    /// explicit lifetime bindings append, and every entry pins its map.
    pub maps: Spinlock<Vec<InodeRef>, TaskListClass>,
}

/// Delegation token derived from a bpffs superblock.
pub struct BpfTokenInode {
    pub source_magic: u64,
    pub flags: u32,
}

pub(crate) const BPF_FS_MAGIC: u64 = 0xcafe4a11;

pub fn make_bpf_token_inode(token: BpfTokenInode) -> InodeRef {
    InodeBuilder::new(ids::INO_TOKEN, mk_mode(FileType::Regular, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(token))
        .build()
}

static NEXT_PROG_ID: AtomicU32 = AtomicU32::new(1);
static PROGRAMS_BY_ID: Spinlock<BTreeMap<u32, Weak<vfs::Inode>>, TaskListClass> =
    Spinlock::new(BTreeMap::new());
static NEXT_MAP_ID: AtomicU32 = AtomicU32::new(1);
static MAPS_BY_ID: Spinlock<BTreeMap<u32, Weak<vfs::Inode>>, TaskListClass> =
    Spinlock::new(BTreeMap::new());
static NEXT_CGROUP_LINK_ID: AtomicU32 = AtomicU32::new(1);
enum CgroupLinkIdSlot {
    Unsettled,
    Settled(Weak<vfs::Inode>),
}
static CGROUP_LINKS_BY_ID: Spinlock<BTreeMap<u32, CgroupLinkIdSlot>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

impl Drop for BpfProgInode {
    fn drop(&mut self) {
        let mut programs = PROGRAMS_BY_ID.lock();
        if programs.get(&self.id).is_some_and(|weak| weak.strong_count() == 0) {
            programs.remove(&self.id);
        }
    }
}

fn next_prog_id() -> u32 {
    loop {
        let id = NEXT_PROG_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 { continue; }
        let mut programs = PROGRAMS_BY_ID.lock();
        match programs.get(&id).and_then(Weak::upgrade) {
            Some(_) => continue,
            None => {
                programs.remove(&id);
                return id;
            }
        }
    }
}

fn prog_by_id(id: u32) -> Option<InodeRef> {
    if id == 0 { return None; }
    let mut programs = PROGRAMS_BY_ID.lock();
    let inode = programs.get(&id).and_then(Weak::upgrade);
    if inode.is_none() { programs.remove(&id); }
    inode
}

fn reserve_cgroup_link_id() -> u32 {
    loop {
        let id = NEXT_CGROUP_LINK_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 { continue; }
        let mut links = CGROUP_LINKS_BY_ID.lock();
        let occupied = match links.get(&id) {
            Some(CgroupLinkIdSlot::Unsettled | CgroupLinkIdSlot::Settled(_)) => true,
            None => false,
        };
        if occupied { continue; }
        links.insert(id, CgroupLinkIdSlot::Unsettled);
        return id;
    }
}

fn cgroup_link_by_id(id: u32) -> Result<InodeRef, Errno> {
    if id == 0 { return Err(Errno::Enoent); }
    let links = CGROUP_LINKS_BY_ID.lock();
    match links.get(&id) {
        Some(CgroupLinkIdSlot::Unsettled) => Err(Errno::Eagain),
        Some(CgroupLinkIdSlot::Settled(link)) => match link.upgrade() {
            Some(inode) => Ok(inode),
            None => Err(Errno::Enoent),
        },
        None => Err(Errno::Enoent),
    }
}

fn settle_cgroup_link_id(id: u32, inode: &InodeRef) {
    let old = CGROUP_LINKS_BY_ID.lock()
        .insert(id, CgroupLinkIdSlot::Settled(Arc::downgrade(inode)));
    hal::kassert!(
        matches!(old, Some(CgroupLinkIdSlot::Unsettled)),
        "settling an unreserved BPF cgroup link ID"
    );
}

fn cancel_cgroup_link_id(id: u32) {
    let mut links = CGROUP_LINKS_BY_ID.lock();
    if matches!(links.get(&id), Some(CgroupLinkIdSlot::Unsettled)) {
        links.remove(&id);
    }
}

/// Primed cgroup link resources. Attachment happens while the ID remains
/// unobservable and fd publication cannot fail. # C: O(fd words + log links)
pub(super) struct BpfCgroupLinkPrimer {
    id: u32,
    fd: i32,
    fdt: Arc<vfs::FdTable>,
    file: Arc<vfs::File>,
    inode: InodeRef,
    settled: bool,
}

impl BpfCgroupLinkPrimer {
    pub(super) fn id(&self) -> u32 { self.id }

    /// Publish the attached object by ID, then install the reserved fd.
    /// # C: O(log links)
    pub(super) fn settle(mut self) -> i64 {
        let link = self.inode.private::<BpfCgroupLinkInode>()
            .expect("BPF cgroup primer inode");
        link.attached.store(true, Ordering::Release);
        settle_cgroup_link_id(self.id, &self.inode);
        self.fdt.fd_install(self.fd, Arc::clone(&self.file));
        self.settled = true;
        self.fd as i64
    }
}

impl Drop for BpfCgroupLinkPrimer {
    fn drop(&mut self) {
        if !self.settled {
            cancel_cgroup_link_id(self.id);
            self.fdt.put_unused_fd(self.fd);
        }
    }
}

/// Reserve the caller's fd before reserving an unsettled link ID.
/// # C: O(fd words + log links)
pub(super) fn prime_bpf_cgroup_link(
    cgid: u64,
    attach_type: cgroup::CgroupBpfAttachType,
    prog: InodeRef,
) -> Result<BpfCgroupLinkPrimer, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on syscall path; table is pinned.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    prime_bpf_cgroup_link_with(fdt, cur.nofile_soft(), cgid, attach_type, prog)
}

fn prime_bpf_cgroup_link_with(
    fdt: Arc<vfs::FdTable>,
    limit: usize,
    cgid: u64,
    attach_type: cgroup::CgroupBpfAttachType,
    prog: InodeRef,
) -> Result<BpfCgroupLinkPrimer, Errno> {
    use vfs::{File, OpenFlags};
    let fd = fdt.get_unused_fd_flags(OpenFlags::O_CLOEXEC, limit)
        .map_err(|_| Errno::Emfile)?;
    let id = reserve_cgroup_link_id();
    let inode = make_bpf_cgroup_link_inode(BpfCgroupLinkInode {
        id, cgid, attach_type, _prog: prog, attached: AtomicBool::new(false),
    });
    let dentry = vfs::dcache::d_alloc_pseudo(
        "bpf-link", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS,
    );
    let file = File::new(Arc::clone(&inode), dentry, OpenFlags::O_RDWR);
    Ok(BpfCgroupLinkPrimer { id, fd, fdt, file, inode, settled: false })
}

/// Build the `Arc<Inode>` for a loaded program (CharDev|0o600,
/// `i_size` = bytecode length). # C: O(1)
pub fn make_bpf_prog_inode(prog_type: u32, insns: Vec<u8>) -> InodeRef {
    make_bpf_prog_inode_with_meta(prog_type, 0, insns, Vec::new())
}

/// Build a loaded program with its attach contract and pinned map references.
/// # C: O(1)
pub fn make_bpf_prog_inode_with_meta(
    prog_type: u32,
    expected_attach_type: u32,
    insns: Vec<u8>,
    maps: Vec<InodeRef>,
) -> InodeRef {
    make_bpf_prog_inode_with_contract(
        prog_type, expected_attach_type, false, insns, maps,
    )
}

/// Build a loaded program with the verifier-derived attach contract.
/// # C: O(1)
pub fn make_bpf_prog_inode_with_contract(
    prog_type: u32,
    expected_attach_type: u32,
    enforce_expected_attach_type: bool,
    insns: Vec<u8>,
    maps: Vec<InodeRef>,
) -> InodeRef {
    let size = insns.len() as u64;
    let id = next_prog_id();
    let inode = InodeBuilder::new(ids::INO_PROG, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .size(size)
        .private(Arc::new(BpfProgInode {
            id, prog_type, expected_attach_type, enforce_expected_attach_type,
            insns, maps: Spinlock::new(maps),
        }))
        .build();
    PROGRAMS_BY_ID.lock().insert(id, Arc::downgrade(&inode));
    inode
}

/// Map value storage is separately locked so a helper can pin a value
/// without holding the map's directory lock while the interpreter runs.
pub struct BpfMapValue {
    pub bytes: Spinlock<Vec<u8>, TaskListClass>,
}

/// Implemented map storage. `map_flags` retains the descriptor and
/// program-access contract; `MapStorage` owns the freeze/writer state.
pub struct BpfMapInode {
    pub id:          u32,
    pub map_type:    u32,
    pub(crate) storage: map::MapStorage,
    pub max_entries: u32,
    pub key_size:    u32,
    pub value_size:  u32,
    pub map_flags:   u32,
}

impl Drop for BpfMapInode {
    fn drop(&mut self) {
        let mut maps = MAPS_BY_ID.lock();
        if maps.get(&self.id).is_some_and(|weak| weak.strong_count() == 0) { maps.remove(&self.id); }
    }
}

pub(crate) fn next_map_id() -> u32 {
    loop {
        let id = NEXT_MAP_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 { continue; }
        let mut maps = MAPS_BY_ID.lock();
        if maps.get(&id).and_then(Weak::upgrade).is_none() { maps.remove(&id); return id; }
    }
}

pub(crate) fn map_by_id(id: u32) -> Option<InodeRef> {
    if id == 0 { return None; }
    let mut maps = MAPS_BY_ID.lock();
    let inode = maps.get(&id).and_then(Weak::upgrade);
    if inode.is_none() { maps.remove(&id); }
    inode
}

pub(crate) fn next_live_map_id(start: u32) -> Option<u32> {
    let mut maps = MAPS_BY_ID.lock();
    let id = maps.range((core::ops::Bound::Excluded(start), core::ops::Bound::Unbounded))
        .find_map(|(id, weak)| weak.upgrade().map(|_| *id));
    maps.retain(|_, weak| weak.strong_count() != 0);
    id
}

/// Build the `Arc<Inode>` for a freshly created BPF map. # C: O(1)
pub fn make_bpf_map_inode(m: BpfMapInode) -> InodeRef {
    let id = m.id;
    let inode = InodeBuilder::new(ids::INO_MAP, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(m))
        .build();
    MAPS_BY_ID.lock().insert(id, Arc::downgrade(&inode));
    inode
}

/// fd-backed BPF LSM link. Dropping the last fd reference removes the
/// registry entry.
pub struct BpfLsmLinkInode {
    id: u64,
    _hook: crate::bpf_lsm::Hook,
    _prog: InodeRef,
}

/// fd-backed cgroup link. The cgroup hierarchy owns attachment state; the
/// link pins its program and removes that exact entry on final close.
pub struct BpfCgroupLinkInode {
    pub(super) id: u32,
    pub(super) cgid: u64,
    pub(super) attach_type: cgroup::CgroupBpfAttachType,
    pub(super) _prog: InodeRef,
    attached: AtomicBool,
}

impl Drop for BpfCgroupLinkInode {
    fn drop(&mut self) {
        if self.attached.load(Ordering::Acquire) {
            let _ = cgroup::bpf::detach_link(self.cgid, self.attach_type, self.id as u64);
            CGROUP_LINKS_BY_ID.lock().remove(&self.id);
        }
    }
}

/// Build an unsettled cgroup BPF link fd inode. # C: O(1)
pub fn make_bpf_cgroup_link_inode(link: BpfCgroupLinkInode) -> InodeRef {
    InodeBuilder::new(ids::INO_LINK, mk_mode(FileType::CharDev, BPF_FD_MODE),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(link))
        .build()
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
    let common = if c & cmd::COMMON_ATTRS != 0 {
        let common = user::fetch_common_attr(args.a3, args.a4 as u32)?;
        c &= !cmd::COMMON_ATTRS;
        Some(common)
    } else { None };
    let caps = caps_now()?;
    match c {
        cmd::MAP_CREATE                 => map::create(&a, caps),
        cmd::MAP_LOOKUP_ELEM            => map::elem(&a, map::MapOp::Lookup),
        cmd::MAP_UPDATE_ELEM            => map::elem(&a, map::MapOp::Update),
        cmd::MAP_DELETE_ELEM            => map::elem(&a, map::MapOp::Delete),
        cmd::MAP_LOOKUP_AND_DELETE_ELEM => map::elem(&a, map::MapOp::LookupAndDelete),
        cmd::MAP_GET_NEXT_KEY           => map::get_next_key(&a),
        cmd::MAP_FREEZE                 => map::freeze(&a),
        cmd::MAP_GET_FD_BY_ID           => map::get_fd_by_id(&a, caps),
        cmd::MAP_GET_NEXT_ID            => map::get_next_id(&a, args.a1, caps),
        cmd::PROG_LOAD                  => prog::load(&a, caps),
        cmd::PROG_ATTACH => prog::attach(&a, false, caps),
        cmd::PROG_DETACH => prog::attach(&a, true, caps),
        cmd::PROG_QUERY                 => prog::query(&a, args.a1, args.a2 as u32, caps),
        cmd::PROG_GET_FD_BY_ID          => prog::get_fd_by_id(&a, caps),
        cmd::PROG_BIND_MAP              => prog::bind_map(&a),
        cmd::LINK_CREATE                => prog::link_create(&a, caps),
        cmd::BTF_LOAD                   => btf::load(
            &a, args.a1, args.a2 as u32, common, caps,
        ),
        cmd::BTF_GET_FD_BY_ID           => btf::get_fd_by_id(&a, caps),
        cmd::BTF_GET_NEXT_ID            => btf::get_next_id(&a, args.a1, caps),
        cmd::OBJ_GET_INFO_BY_FD         => btf::get_info_by_fd(&a, args.a1),
        cmd::TOKEN_CREATE                => token::create(&a),
        // `__sys_bpf()`'s `default: err = -EINVAL`, reached only after
        // the attr size protocol above has had its say.
        _ => Err(Errno::Einval),
    }
}

/// Effective capability snapshot. `bpf_capable()` and friends fold
/// CAP_SYS_ADMIN in, which [`Caps`] models.
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

/// Publish a BPF object on a descriptor that must not survive `execve`.
/// # C: O(fd words)
pub(super) fn install_fd(inode: InodeRef, name: &str) -> Result<i64, Errno> {
    install_fd_access(inode, name, vfs::OpenFlags::O_RDWR)
}

/// Publish one descriptor with the requested access mode and close-on-exec.
/// # C: O(fd words)
pub(super) fn install_fd_access(
    inode: InodeRef,
    name: &str,
    access: vfs::OpenFlags,
) -> Result<i64, Errno> {
    use vfs::{File, OpenFlags};
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let dentry = vfs::dcache::d_alloc_pseudo(name, Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode, dentry, access);
    // `alloc_fd_flags_below` fails only with EMFILE (RLIMIT_NOFILE),
    // matching `get_unused_fd_flags()`.
    fdt.install_limit(file, OpenFlags::O_CLOEXEC, cur.nofile_soft())
        .map(|fd| fd as i64)
        .map_err(|_| Errno::Emfile)
}
