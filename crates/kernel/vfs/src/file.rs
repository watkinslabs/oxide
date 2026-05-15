// `File` per `16§5`. The kernel-side handle that an FD entry points
// to: cached inode / dentry, current position, open flags. Per-process
// FD table lives in `fdtable.rs`.

extern crate alloc;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{KResult, OpenFlags, VfsError};

/// Backing handle for an open file. Stored as `Arc<File>` so dup / fork
/// share the position cursor per POSIX (`15§2`).
pub struct File {
    inode:  InodeRef,
    dentry: Arc<Dentry>,
    pos:    AtomicU64,
    flags:  AtomicU32,
    /// Currently-held flock kind: 0=none, 1=LOCK_SH, 2=LOCK_EX. Used
    /// by the kernel-side flock registry to find which lock to drop
    /// when the last reference to this open-file-description goes
    /// away (Drop impl below).
    pub flock_op: AtomicU32,
    /// F_GETOWN/F_SETOWN target: positive = tid, negative = -pgid, 0 = none.
    /// SIGIO/SIGURG delivery routes to this id when fasync fires.
    pub owner: core::sync::atomic::AtomicI32,
}

/// Kernel-side hook installed at boot. Called from `File::drop` for
/// the last-Arc-reference release (close+last-dup gone). The kernel
/// flock module installs a release fn that walks the per-inode
/// registry. `0` = no hook installed (host tests, early boot).
static FLOCK_RELEASE_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the per-File drop hook used by `flock(2)` to release any
/// held lock. Called once at kernel init. The `usize` argument the
/// hook receives is the dropped File's `&self` raw pointer cast.
/// # C: O(1)
pub fn set_drop_hook(f: fn(usize, &InodeRef)) {
    FLOCK_RELEASE_HOOK.store(f as u64, Ordering::Release);
}

/// Kernel-side write hook called from `File::write` after a successful
/// inode write. Used by the inotify subsystem to fire IN_MODIFY events.
/// `0` = no hook installed.
static WRITE_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the post-write hook used by inotify(7) to fire IN_MODIFY.
/// # C: O(1)
pub fn set_write_hook(f: fn(&InodeRef)) {
    WRITE_HOOK.store(f as u64, Ordering::Release);
}

static OPEN_HOOK:  AtomicU64 = AtomicU64::new(0);
static READ_HOOK:  AtomicU64 = AtomicU64::new(0);

/// Close-hook slot table per `16§R02`. Multiple subsystems register
/// here (inotify IN_CLOSE_*, pipe writer/reader-count tracking, …);
/// every slot fires in `File::Drop`. Fixed N=4 covers the in-kernel
/// subsystems we have; extend if a new consumer arrives.
const CLOSE_HOOK_SLOTS: usize = 4;
static CLOSE_HOOKS: [AtomicU64; CLOSE_HOOK_SLOTS] =
    [const { AtomicU64::new(0) }; CLOSE_HOOK_SLOTS];

/// Install the open hook (fires IN_OPEN at File::new).
/// # C: O(1)
pub fn set_open_hook(f: fn(&InodeRef))  { OPEN_HOOK.store(f as u64, Ordering::Release); }

/// Install the read hook (fires IN_ACCESS after File::read returns >0).
/// # C: O(1)
pub fn set_read_hook(f: fn(&InodeRef))  { READ_HOOK.store(f as u64, Ordering::Release); }

/// Install a close hook (fires at `File::Drop`). Bool argument is
/// true when the closed File was opened writable. Picks the next
/// free slot in the registry; panics if full so misconfiguration
/// is loud rather than silent.
/// # C: O(N) slot scan; N=4 fixed.
pub fn set_close_hook(f: fn(&InodeRef, bool)) {
    for slot in CLOSE_HOOKS.iter() {
        if slot.compare_exchange(0, f as u64, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return;
        }
    }
    hal::kassert!(false, "CLOSE_HOOKS table full");
}

/// Dirent-mutation hooks per `16§R02`. Fired by devfs / tmpfs path-
/// registry mutations so inotify watches on the parent directory
/// can dispatch IN_CREATE / IN_DELETE / IN_MOVED with the new dirent
/// name. Args: (parent_path, leaf_name).
static DIRENT_CREATE_HOOK: AtomicU64 = AtomicU64::new(0);
static DIRENT_DELETE_HOOK: AtomicU64 = AtomicU64::new(0);

/// # C: O(1)
pub fn set_dirent_create_hook(f: fn(&str, &str)) {
    DIRENT_CREATE_HOOK.store(f as u64, Ordering::Release);
}
/// # C: O(1)
pub fn set_dirent_delete_hook(f: fn(&str, &str)) {
    DIRENT_DELETE_HOOK.store(f as u64, Ordering::Release);
}

/// Fire the dirent-create hook (no-op when not installed).
/// # C: O(1)
pub fn fire_dirent_create(parent: &str, leaf: &str) {
    let h = DIRENT_CREATE_HOOK.load(Ordering::Acquire);
    if h == 0 { return; }
    // SAFETY: h was installed by `set_dirent_create_hook` with the
    // documented signature.
    let f: fn(&str, &str) = unsafe { core::mem::transmute(h) };
    f(parent, leaf);
}

/// Fire the dirent-delete hook (no-op when not installed).
/// # C: O(1)
pub fn fire_dirent_delete(parent: &str, leaf: &str) {
    let h = DIRENT_DELETE_HOOK.load(Ordering::Acquire);
    if h == 0 { return; }
    // SAFETY: h was installed by `set_dirent_delete_hook` with the
    // documented signature.
    let f: fn(&str, &str) = unsafe { core::mem::transmute(h) };
    f(parent, leaf);
}

impl Drop for File {
    fn drop(&mut self) {
        if self.flock_op.load(Ordering::Acquire) != 0 {
            let h = FLOCK_RELEASE_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_drop_hook` with a real fn(usize, &InodeRef) pointer.
                let f: fn(usize, &InodeRef) = unsafe { core::mem::transmute(h) };
                f(self as *const Self as usize, &self.inode);
            }
        }
        // Close-hook chain: inotify IN_CLOSE_*, pipe writer/reader
        // tracking, etc. Every installed slot fires.
        let was_writable = {
            let bits = self.flags.load(Ordering::Acquire);
            let f = OpenFlags::from_bits_retain(bits);
            f.contains(OpenFlags::O_WRONLY) || f.contains(OpenFlags::O_RDWR)
        };
        for slot in CLOSE_HOOKS.iter() {
            let h = slot.load(Ordering::Acquire);
            if h == 0 { continue; }
            // SAFETY: slot value installed via set_close_hook with the documented fn(&InodeRef, bool) signature; reinterpret round-trips that exact type.
            let f: fn(&InodeRef, bool) = unsafe { core::mem::transmute(h) };
            f(&self.inode, was_writable);
        }
    }
}

impl File {
    /// # C: O(1)
    pub fn new(inode: InodeRef, dentry: Arc<Dentry>, flags: OpenFlags) -> Arc<Self> {
        let h = OPEN_HOOK.load(Ordering::Acquire);
        if h != 0 {
            // SAFETY: h was installed by `set_open_hook` with a real fn(&InodeRef) pointer.
            let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
            f(&inode);
        }
        Arc::new(Self {
            inode,
            dentry,
            pos:   AtomicU64::new(0),
            flags: AtomicU32::new(flags.bits()),
            flock_op: AtomicU32::new(0),
            owner: core::sync::atomic::AtomicI32::new(0),
        })
    }

    /// # C: O(1)
    pub fn inode(&self) -> &InodeRef { &self.inode }

    /// # C: O(1)
    pub fn dentry(&self) -> &Arc<Dentry> { &self.dentry }

    /// Snapshot of the file position.
    /// # C: O(1)
    pub fn pos(&self) -> u64 { self.pos.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_pos(&self, p: u64) { self.pos.store(p, Ordering::Release); }

    /// Snapshot of open flags.
    /// # C: O(1)
    pub fn flags(&self) -> OpenFlags {
        OpenFlags::from_bits_retain(self.flags.load(Ordering::Acquire))
    }

    /// # C: O(1)
    pub fn set_flags(&self, f: OpenFlags) {
        self.flags.store(f.bits(), Ordering::Release);
    }

    /// `read(2)` — advances the cursor by the byte count returned by
    /// the inode's `read`. Rejects writes-only opens with `Ebadf`.
    /// O_NONBLOCK routes through `Inode::read_nonblock`, which the
    /// blocking inodes (pipe/pty/tty/socket) override to return
    /// `EAGAIN` instead of parking.
    /// # C: depends on inode impl
    pub fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let f = self.flags();
        if f.contains(OpenFlags::O_WRONLY) {
            return Err(VfsError::Ebadf);
        }
        let pos = self.pos.load(Ordering::Acquire);
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.inode.read_nonblock(pos, buf)?
        } else {
            self.inode.read(pos, buf)?
        };
        self.pos.store(pos + n as u64, Ordering::Release);
        if n > 0 {
            let h = READ_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_read_hook` with a real fn(&InodeRef) pointer.
                let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
                f(&self.inode);
            }
        }
        Ok(n)
    }

    /// `write(2)` — advances the cursor by the byte count returned by
    /// the inode's `write`. Rejects read-only opens with `Ebadf`.
    /// `O_APPEND` snaps the offset to the current size before writing.
    /// # C: depends on inode impl
    pub fn write(&self, buf: &[u8]) -> KResult<usize> {
        let f = self.flags();
        if !(f.contains(OpenFlags::O_WRONLY) || f.contains(OpenFlags::O_RDWR)) {
            return Err(VfsError::Ebadf);
        }
        let off = if f.contains(OpenFlags::O_APPEND) {
            self.inode.size()
        } else {
            self.pos.load(Ordering::Acquire)
        };
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.inode.write_nonblock(off, buf)?
        } else {
            self.inode.write(off, buf)?
        };
        self.pos.store(off + n as u64, Ordering::Release);
        // inotify IN_MODIFY hook (no-op when nothing installed).
        if n > 0 {
            let h = WRITE_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_write_hook` with a real fn(&InodeRef) pointer; the cast back to that signature is the documented-shape contract.
                let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
                f(&self.inode);
            }
        }
        Ok(n)
    }

    /// `lseek(2)` SEEK_SET / CUR / END. Returns the new position.
    /// # C: O(1)
    pub fn seek(&self, whence: SeekFrom, off: i64) -> KResult<u64> {
        let new_pos = match whence {
            SeekFrom::Start   => off as u64,
            SeekFrom::Current => {
                let cur = self.pos.load(Ordering::Acquire) as i64;
                cur.checked_add(off).ok_or(VfsError::Einval)? as u64
            }
            SeekFrom::End => {
                let end = self.inode.size() as i64;
                end.checked_add(off).ok_or(VfsError::Einval)? as u64
            }
        };
        self.pos.store(new_pos, Ordering::Release);
        Ok(new_pos)
    }
}

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("File")
            .field("ino", &self.inode.ino())
            .field("pos", &self.pos())
            .field("flags", &self.flags())
            .finish()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SeekFrom {
    Start,
    Current,
    End,
}


/// Create a `File` from an inode + path, install into the supplied
/// `FdTable`. Per `docs/53§3` Tier-2 work fn. Handles the common
/// post-lookup sequence: O_DIRECTORY check, O_TRUNC, Dentry wrap,
/// File construction, fd allocation.
/// # C: O(1) + fd_table alloc
pub fn install_open(
    fdt: &crate::fdtable::FdTable,
    inode: InodeRef,
    path: &str,
    flags: OpenFlags,
) -> Result<i32, VfsError> {
    use alloc::sync::Arc;
    use alloc::string::ToString;
    use crate::dentry::Dentry;
    if flags.contains(OpenFlags::O_DIRECTORY)
        && !matches!(inode.file_type(), crate::types::FileType::Directory)
    {
        return Err(VfsError::Enotdir);
    }
    if flags.contains(OpenFlags::O_TRUNC) {
        let _ = inode.truncate(0);
    }
    let dentry = Dentry::new(None, path.to_string(), Arc::clone(&inode));
    let file = File::new(inode, dentry, flags);
    fdt.alloc(file).map_err(|_| VfsError::Emfile)
}
