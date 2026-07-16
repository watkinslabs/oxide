//! Built-in Linux autofs filesystem surface.

extern crate alloc;

mod autofs_ids {
    pub(crate) const ROOT_INO: u64 = 0x0187_0001;
    pub(crate) const CONTROL_INO_BASE: u64 = 0x0187_1000;
    pub(crate) const CONTROL_INO_MASK: u64 = 0x0fff;
}

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{Spinlock, TaskList as LockClass};

use vfs::{File, FileType, Inode, InodeOps, InodeRef, KResult, VfsError};
use vfs::{DirContext, FileOps, InodeBuilder, default_file_ops, default_inode_ops, mk_mode};

#[cfg(target_os = "oxide-kernel")]
use sched::live::WaitList;

#[cfg(not(target_os = "oxide-kernel"))]
struct WaitList;

#[cfg(not(target_os = "oxide-kernel"))]
impl WaitList {
    const fn new() -> Self { Self }
    fn wake_all(&self) {}
    unsafe fn park(&self) { unreachable!("autofs wait under hosted"); }
}

#[cfg(target_os = "oxide-kernel")]
fn deliverable_signals_self() -> u64 { sched::live::deliverable_signals_self() }

#[cfg(not(target_os = "oxide-kernel"))]
fn deliverable_signals_self() -> u64 { 0 }

#[cfg(target_os = "oxide-kernel")]
unsafe fn schedule_now() { unsafe { sched::live::schedule::schedule(); } }

#[cfg(not(target_os = "oxide-kernel"))]
unsafe fn schedule_now() { unreachable!("autofs schedule under hosted"); }

pub const AUTOFS_SUPER_MAGIC: u64 = 0x0187;
const AUTOFS_PROTO_VERSION: u32 = 5;
const AUTOFS_PROTO_SUBVERSION: u32 = 6;
const AUTOFS_PTYPE_MISSING_DIRECT: i32 = 5;

pub struct AutofsFs {
    root: InodeRef,
    state: Arc<AutofsState>,
}

impl AutofsFs {
    pub fn new(options: &str) -> KResult<Arc<Self>> {
        let pipe = match parse_fd_option(options) {
            Some(fd) => Some(resolve_fd(fd)?),
            None => None,
        };
        let state = Arc::new(AutofsState::new(pipe));
        Ok(Arc::new(Self {
            root: make_autofs_root(Arc::clone(&state)),
            state,
        }))
    }
}

impl vfs::fs::FileSystem for AutofsFs {
    fn name(&self) -> &str { "autofs" }
    fn magic(&self) -> u64 { AUTOFS_SUPER_MAGIC }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    fn set_sb(&self, sb: alloc::sync::Weak<vfs::superblock::SuperBlock>) -> vfs::KResult<()> {
        if let Some(sb) = sb.upgrade() {
            // `state.dev` holds the RAW `s_dev` so `AutofsRoot::fsid` reports it
            // and `fstat(mountpoint)` yields `fsid_to_dev(s_dev)` (the stat ABI).
            // The registry is keyed on that SAME user-visible dev: systemd's
            // `AUTOFS_DEV_IOCTL_OPENMOUNT` passes the `devid` it took from
            // `fstat`, so keying on the raw 64-bit anon `s_dev` never matched —
            // the ioctl returned ENOENT and wedged PID1 in an endless umount
            // retry of `proc-sys-fs-binfmt_misc.automount`.
            self.state.dev.store(sb.s_dev, Ordering::Release);
            self.root.set_fsid(sb.s_dev);
            register_mount(vfs::fsid_to_dev(sb.s_dev), Arc::clone(&self.state));
        }
        Ok(())
    }
}

/// Per-inode autofs root state (Linux `i_private`).
struct AutofsRootData { state: Arc<AutofsState> }

/// `make_autofs_root(state)` — the autofs mount-point directory inode. # C: O(1)
fn make_autofs_root(state: Arc<AutofsState>) -> InodeRef {
    InodeBuilder::new(autofs_ids::ROOT_INO, mk_mode(FileType::Directory, 0o755),
        Arc::new(AutofsRootInodeOps), Arc::new(AutofsRootFileOps))
        .private(Arc::new(AutofsRootData { state }))
        .build()
}

/// `i_op` for the autofs root: a lookup triggers an automount request. # C: O(1)
struct AutofsRootInodeOps;
impl InodeOps for AutofsRootInodeOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<AutofsRootData>().ok_or(VfsError::Einval)?;
        d.state.trigger(name)?;
        Err(VfsError::Enoent)
    }
}

/// `i_fop` for the autofs root: an empty directory. # C: O(1)
struct AutofsRootFileOps;
impl FileOps for AutofsRootFileOps {
    fn iterate(&self, _inode: &Inode, _ctx: &mut DirContext) -> KResult<()> {
        Ok(())
    }
}

/// Per-inode autofs control state (`AUTOFS_DEV_IOCTL_OPENMOUNT`'s fd target).
/// Kept as the public type downstream ioctl handlers downcast to. # C: O(1)
pub struct AutofsCtlInode {
    state: Arc<AutofsState>,
}

/// `make_autofs_ctl_inode(state)` — a CharDev ioctl-only inode. # C: O(1)
fn make_autofs_ctl_inode(state: Arc<AutofsState>) -> InodeRef {
    let ino = autofs_ids::CONTROL_INO_BASE
        | (state.dev.load(Ordering::Acquire) & autofs_ids::CONTROL_INO_MASK);
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0),
        default_inode_ops(), default_file_ops())
        .private(Arc::new(AutofsCtlInode { state }))
        .build()
}

pub fn ctl_from_inode(inode: &InodeRef) -> Option<&AutofsCtlInode> {
    inode.private::<AutofsCtlInode>()
}

struct Pending {
    token: u32,
    done: bool,
    status: i32,
}

struct AutofsState {
    dev: AtomicU64,
    pipe: Spinlock<Option<Arc<File>>, LockClass>,
    timeout: AtomicU64,
    next_token: AtomicU32,
    pending: Spinlock<Option<Pending>, LockClass>,
    waiters: WaitList,
}

impl AutofsState {
    fn new(pipe: Option<Arc<File>>) -> Self {
        Self {
            dev: AtomicU64::new(0),
            pipe: Spinlock::new(pipe),
            timeout: AtomicU64::new(300),
            next_token: AtomicU32::new(1),
            pending: Spinlock::new(None),
            waiters: WaitList::new(),
        }
    }

    fn trigger(&self, name: &str) -> KResult<()> {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        {
            let mut p = self.pending.lock();
            if p.is_some() {
                return Err(VfsError::Ebusy);
            }
            *p = Some(Pending { token, done: false, status: 0 });
        }
        if let Err(e) = self.write_missing_packet(token, name) {
            *self.pending.lock() = None;
            return Err(e);
        }
        loop {
            {
                let p = self.pending.lock();
                if let Some(pending) = p.as_ref() {
                    if pending.token == token && pending.done {
                        let status = pending.status;
                        drop(p);
                        *self.pending.lock() = None;
                        return status_to_result(status);
                    }
                } else {
                    return Err(VfsError::Enoent);
                }
            }
            if deliverable_signals_self() != 0 {
                self.cancel_pending(token);
                return Err(VfsError::Eintr);
            }
            unsafe { self.waiters.park(); }
            unsafe { schedule_now(); }
        }
    }

    fn write_missing_packet(&self, token: u32, name: &str) -> KResult<()> {
        let file = self.pipe.lock().as_ref().cloned().ok_or(VfsError::Enoent)?;
        let cur = sched::current().ok_or(VfsError::Ebadf)?;
        let mut packet = [0u8; 304];
        write_i32(&mut packet, 0, AUTOFS_PROTO_VERSION as i32);
        write_i32(&mut packet, 4, AUTOFS_PTYPE_MISSING_DIRECT);
        write_u32(&mut packet, 8, token);
        write_u32(&mut packet, 12, self.dev.load(Ordering::Acquire) as u32);
        write_u64(&mut packet, 16, self.ino());
        write_u32(&mut packet, 24, 0);
        write_u32(&mut packet, 28, 0);
        let pid = cur.tid;
        write_u32(&mut packet, 32, pid);
        write_u32(&mut packet, 36, pid);
        let bytes = name.as_bytes();
        let n = bytes.len().min(255);
        write_u32(&mut packet, 40, n as u32);
        packet[44..44 + n].copy_from_slice(&bytes[..n]);
        let wrote = file.write(&packet).map_err(|_| VfsError::Eio)?;
        if wrote == packet.len() { Ok(()) } else { Err(VfsError::Eio) }
    }

    fn ino(&self) -> u64 { 0x0187_0001 }

    fn ready(&self, token: u32, status: i32) -> i64 {
        let mut p = self.pending.lock();
        match p.as_mut() {
            Some(pending) if pending.token == token => {
                pending.done = true;
                pending.status = status;
                drop(p);
                self.waiters.wake_all();
                0
            }
            _ => -(syscall::errno::Errno::Enoent.as_i32() as i64),
        }
    }

    fn cancel_pending(&self, token: u32) {
        let mut p = self.pending.lock();
        if p.as_ref().is_some_and(|pending| pending.token == token) {
            *p = None;
            drop(p);
            self.waiters.wake_all();
        }
    }

    fn set_pipe_fd(&self, fd: i32) -> KResult<()> {
        let file = resolve_fd(fd)?;
        *self.pipe.lock() = Some(file);
        Ok(())
    }

    fn timeout(&self, requested: u64) -> u64 {
        if requested != 0 {
            self.timeout.store(requested, Ordering::Release);
        }
        self.timeout.load(Ordering::Acquire)
    }
}

static MOUNTS: Spinlock<Option<BTreeMap<u64, Arc<AutofsState>>>, LockClass> = Spinlock::new(None);

fn mounts() -> BTreeMap<u64, Arc<AutofsState>> {
    MOUNTS.lock().as_ref().cloned().unwrap_or_default()
}

fn register_mount(dev: u64, state: Arc<AutofsState>) {
    let mut g = MOUNTS.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
    g.as_mut().unwrap().insert(dev, state);
}

pub fn openmount(devid: u32) -> Option<InodeRef> {
    let dev = devid as u64;
    mounts().get(&dev).cloned().map(make_autofs_ctl_inode)
}

pub fn ctl_protover(ctl: &AutofsCtlInode) -> u32 {
    let _ = ctl;
    AUTOFS_PROTO_VERSION
}

pub fn ctl_protosubver(ctl: &AutofsCtlInode) -> u32 {
    let _ = ctl;
    AUTOFS_PROTO_SUBVERSION
}

pub fn ctl_ready(ctl: &AutofsCtlInode, token: u32) -> i64 {
    ctl.state.ready(token, 0)
}

pub fn ctl_fail(ctl: &AutofsCtlInode, token: u32, status: i32) -> i64 {
    ctl.state.ready(token, status)
}

pub fn ctl_setpipefd(ctl: &AutofsCtlInode, fd: i32) -> KResult<()> {
    ctl.state.set_pipe_fd(fd)
}

pub fn ctl_timeout(ctl: &AutofsCtlInode, requested: u64) -> u64 {
    ctl.state.timeout(requested)
}

fn parse_fd_option(options: &str) -> Option<i32> {
    for part in options.split(',') {
        let Some(v) = part.strip_prefix("fd=") else { continue; };
        if let Ok(fd) = v.parse::<i32>() {
            return Some(fd);
        }
    }
    None
}

fn resolve_fd(fd: i32) -> KResult<Arc<File>> {
    let cur = sched::current().ok_or(VfsError::Ebadf)?;
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(VfsError::Ebadf)?.clone();
    fdt.get(fd)
}

fn status_to_result(status: i32) -> KResult<()> {
    let errno = if status < 0 { -status } else { status };
    match errno {
        0 => Ok(()),
        1 => Err(VfsError::Eperm),
        2 => Err(VfsError::Enoent),
        4 => Err(VfsError::Eintr),
        5 => Err(VfsError::Eio),
        6 => Err(VfsError::Enxio),
        9 => Err(VfsError::Ebadf),
        11 => Err(VfsError::Eagain),
        12 => Err(VfsError::Enomem),
        13 => Err(VfsError::Eacces),
        14 => Err(VfsError::Efault),
        16 => Err(VfsError::Ebusy),
        17 => Err(VfsError::Eexist),
        18 => Err(VfsError::Exdev),
        19 => Err(VfsError::Enodev),
        20 => Err(VfsError::Enotdir),
        21 => Err(VfsError::Eisdir),
        22 => Err(VfsError::Einval),
        24 => Err(VfsError::Emfile),
        25 => Err(VfsError::Enotty),
        28 => Err(VfsError::Enospc),
        29 => Err(VfsError::Espipe),
        30 => Err(VfsError::Erofs),
        32 => Err(VfsError::Epipe),
        36 => Err(VfsError::Enametoolong),
        38 => Err(VfsError::Enosys),
        39 => Err(VfsError::Enotempty),
        40 => Err(VfsError::Eloop),
        95 => Err(VfsError::Eopnotsupp),
        107 => Err(VfsError::Enotconn),
        _ => Err(VfsError::Enoent),
    }
}

fn write_u32(dst: &mut [u8], off: usize, v: u32) {
    dst[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}
fn write_i32(dst: &mut [u8], off: usize, v: i32) {
    dst[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}
fn write_u64(dst: &mut [u8], off: usize, v: u64) {
    dst[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}
