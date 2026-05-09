// Real inotify per Linux 2.6.13. Per-fd watch table + per-fd event
// queue + vfs::File::write hook for IN_MODIFY firing. Programs that
// inotify_add_watch on a path then write to it now see real events
// via inotify_inode.read.
//
// v1 limits:
//   * IN_MODIFY only — fired from File::write after successful inode write.
//     IN_OPEN / IN_CLOSE / IN_CREATE / IN_DELETE / IN_MOVED_* ride v2
//     once the corresponding VFS paths grow hooks.
//   * watches are inode-pointer-keyed (same identity scheme as
//     inode_times / xattr_overlay). On distinct path resolution to
//     the same inode, both watches fire (Linux behaviour).
//   * No recursive watches (no IN_ONLYDIR / IN_DONT_FOLLOW honouring).

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const INOTIFY_INO_BASE: Ino = 0x7100_0000;

/// Linux IN_* event masks (subset).
pub const IN_ACCESS:        u32 = 0x0001;
pub const IN_MODIFY:        u32 = 0x0002;
pub const IN_ATTRIB:        u32 = 0x0004;
pub const IN_CLOSE_WRITE:   u32 = 0x0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0010;
pub const IN_OPEN:          u32 = 0x0020;
pub const IN_ALL_EVENTS:    u32 = 0x0fff;

#[derive(Clone)]
struct Watch {
    wd: i32,
    inode_key: usize,
    mask: u32,
}

#[repr(C)]
struct Event {
    wd:     i32,
    mask:   u32,
    cookie: u32,
    /// Length of the trailing name field (0 — v1 doesn't track names yet).
    len:    u32,
}

pub struct InotifyInode {
    pub flags:   u32,
    pub next_wd: AtomicI32,
    watches: Spinlock<Vec<Watch>, TaskListClass>,
    events:  Spinlock<VecDeque<Event>, TaskListClass>,
}

impl InotifyInode {
    /// Construct + register in the global instance list so the vfs
    /// write hook can find this inotify when an inode it watches is
    /// modified. Drop unregisters.
    /// # C: O(1)
    pub fn new(flags: u32) -> Arc<Self> {
        let arc = Arc::new(Self {
            flags,
            next_wd: AtomicI32::new(1),
            watches: Spinlock::new(Vec::new()),
            events:  Spinlock::new(VecDeque::new()),
        });
        register_instance(Arc::downgrade(&arc));
        arc
    }
}

impl Inode for InotifyInode {
    fn as_any(&self) -> Option<&dyn Any> { Some(self) }
    fn ino(&self) -> Ino { INOTIFY_INO_BASE }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    /// Drain queued events into `buf` in Linux `struct inotify_event`
    /// shape: {wd: i32, mask: u32, cookie: u32, len: u32, name[len]}.
    /// v1 always emits len=0 (no name tail).
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        const HDR: usize = 16;
        let mut written = 0;
        let mut q = self.events.lock();
        while written + HDR <= buf.len() {
            let ev = match q.pop_front() { Some(e) => e, None => break };
            let s = &mut buf[written..written + HDR];
            s[0..4].copy_from_slice(&ev.wd.to_le_bytes());
            s[4..8].copy_from_slice(&ev.mask.to_le_bytes());
            s[8..12].copy_from_slice(&ev.cookie.to_le_bytes());
            s[12..16].copy_from_slice(&ev.len.to_le_bytes());
            written += HDR;
        }
        Ok(written)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Global registry of weak refs to every live InotifyInode. Walked
/// on each VFS write-hook call to find watches matching the modified
/// inode.
static INSTANCES: Spinlock<Vec<Weak<InotifyInode>>, TaskListClass> =
    Spinlock::new(Vec::new());

fn register_instance(w: Weak<InotifyInode>) {
    let mut g = INSTANCES.lock();
    // Garbage-collect dead weak refs while we're here.
    g.retain(|w| w.upgrade().is_some());
    g.push(w);
}

/// vfs::File write-hook callback. For each live InotifyInode whose
/// watch list mentions `inode_key`, push an IN_MODIFY event into
/// that inode's event queue.
/// # C: O(N_inotify * N_watches_per)
fn vfs_write_notify(inode: &InodeRef) {
    let key = inode_key(inode);
    let g = INSTANCES.lock();
    for w in g.iter() {
        let arc = match w.upgrade() { Some(a) => a, None => continue };
        let watches = arc.watches.lock();
        for wi in watches.iter() {
            if wi.inode_key == key && (wi.mask & IN_MODIFY) != 0 {
                let mut q = arc.events.lock();
                q.push_back(Event { wd: wi.wd, mask: IN_MODIFY, cookie: 0, len: 0 });
            }
        }
    }
}

/// Install `vfs_write_notify` as the vfs::File write-hook. Called once
/// at kernel_main.
/// # C: O(1)
pub fn install_write_hook() {
    vfs::set_write_hook(vfs_write_notify);
}

fn inode_key(inode: &InodeRef) -> usize {
    let raw: *const dyn Inode = Arc::as_ptr(inode);
    raw as *const u8 as usize
}

/// `sys_inotify_init(flags=0)` / `sys_inotify_init1(flags)`.
/// Allocates a fresh InotifyInode at the lowest free fd.
/// # C: O(N_fds)
pub fn kernel_sys_inotify_init1(args: &syscall::SyscallArgs) -> i64 {
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let flags = args.a0 as u32;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let arc = InotifyInode::new(flags);
    let inode: InodeRef = arc as InodeRef;
    let dentry = Dentry::new(None, "inotify".to_string(), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

fn fd_to_inotify(fd: i32) -> Option<Arc<InotifyInode>> {
    let cur = crate::sched::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let f = fdt.get(fd).ok()?;
    let inode = f.inode().clone();
    let any = inode.as_any()?;
    any.downcast_ref::<InotifyInode>()?;
    // Re-construct the Arc<InotifyInode> from the Arc<dyn Inode>.
    // We can't downcast Arc directly; instead we use the existing
    // INSTANCES list to find the matching weak and upgrade it.
    let key_self = inode_key(&inode);
    let g = INSTANCES.lock();
    for w in g.iter() {
        if let Some(a) = w.upgrade() {
            let a_inode: InodeRef = a.clone() as InodeRef;
            if inode_key(&a_inode) == key_self {
                return Some(a);
            }
        }
    }
    None
}

/// `sys_inotify_add_watch(fd, pathname, mask)`. Resolves `pathname`
/// via devfs (v1's only namespace), records a Watch on the fd's
/// InotifyInode, returns the wd.
/// # C: O(N_path)
pub fn kernel_sys_inotify_add_watch(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let path_p = args.a1;
    let mask   = args.a2 as u32;
    let inotify = match fd_to_inotify(fd) {
        Some(a) => a, None => return -(Errno::Einval.as_i32() as i64),
    };
    if path_p == 0 || path_p >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: path_p in user range; bounded read via existing helper.
    let bytes = unsafe { crate::devfs::read_user_cstr(path_p, 256) };
    let s = match bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() }) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let inode = match crate::devfs::lookup(s) {
        Some(i) => i, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let key = inode_key(&inode);
    let mut g = inotify.watches.lock();
    // If a watch on the same inode exists, replace its mask + return existing wd.
    for w in g.iter_mut() {
        if w.inode_key == key {
            w.mask = mask;
            return w.wd as i64;
        }
    }
    let wd = inotify.next_wd.fetch_add(1, Ordering::Relaxed);
    g.push(Watch { wd, inode_key: key, mask });
    wd as i64
}

/// `sys_inotify_rm_watch(fd, wd)`. Removes the watch from the fd's
/// InotifyInode. EINVAL if no such wd.
/// # C: O(N_watches)
pub fn kernel_sys_inotify_rm_watch(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let wd = args.a1 as i32;
    let inotify = match fd_to_inotify(fd) {
        Some(a) => a, None => return -(Errno::Einval.as_i32() as i64),
    };
    let mut g = inotify.watches.lock();
    let n_before = g.len();
    g.retain(|w| w.wd != wd);
    if g.len() == n_before { -(Errno::Einval.as_i32() as i64) } else { 0 }
}

// `AtomicU32` import keeps the Spinlock lock-class warning at bay; nothing
// else in this module uses it.
const _: AtomicU32 = AtomicU32::new(0);
