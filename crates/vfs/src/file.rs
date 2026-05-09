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
static CLOSE_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the open hook (fires IN_OPEN at File::new).
/// # C: O(1)
pub fn set_open_hook(f: fn(&InodeRef))  { OPEN_HOOK.store(f as u64, Ordering::Release); }

/// Install the read hook (fires IN_ACCESS after File::read returns >0).
/// # C: O(1)
pub fn set_read_hook(f: fn(&InodeRef))  { READ_HOOK.store(f as u64, Ordering::Release); }

/// Install the close hook (fires IN_CLOSE_WRITE / IN_CLOSE_NOWRITE
/// at File::Drop). Bool argument is true when the closed File was
/// opened writable.
/// # C: O(1)
pub fn set_close_hook(f: fn(&InodeRef, bool)) {
    CLOSE_HOOK.store(f as u64, Ordering::Release);
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
        // inotify IN_CLOSE_WRITE / IN_CLOSE_NOWRITE.
        let h = CLOSE_HOOK.load(Ordering::Acquire);
        if h != 0 {
            let was_writable = {
                let bits = self.flags.load(Ordering::Acquire);
                let f = OpenFlags::from_bits_retain(bits);
                f.contains(OpenFlags::O_WRONLY) || f.contains(OpenFlags::O_RDWR)
            };
            // SAFETY: h was installed by `set_close_hook` with a real fn(&InodeRef, bool) pointer.
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
    /// # C: depends on inode impl
    pub fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let f = self.flags();
        if f.contains(OpenFlags::O_WRONLY) {
            return Err(VfsError::Ebadf);
        }
        let pos = self.pos.load(Ordering::Acquire);
        let n = self.inode.read(pos, buf)?;
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
        let n = self.inode.write(off, buf)?;
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
