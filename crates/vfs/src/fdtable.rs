// Per-process FD table per `16§5`. Vec<Option<Arc<File>>> + cloexec
// bitset, both under a single per-process spinlock (class `FdTable`,
// `06§3.6`). Shared via `CLONE_FILES` (`Arc<FdTable>`).
//
// Operations are the minimum set needed by `15§2` syscalls 0..=24
// (read/write/close/dup/dup2/dup3, plus the `*at` family's "alloc fd
// for newly opened file" path).

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{FdTable as FdTableClass, Spinlock};

use crate::file::File;
use crate::types::{KResult, VfsError};

/// Soft limit on FDs per process. Linux's default `RLIMIT_NOFILE` is
/// 1024; raise to 64 KiB once cgroup-tracked rlimits land.
pub const FD_TABLE_MAX: usize = 1024;

#[derive(Default)]
struct FdTableInner {
    files:   Vec<Option<Arc<File>>>,
    cloexec: Vec<bool>,
}

impl FdTableInner {
    fn ensure_capacity(&mut self, idx: usize) {
        if self.files.len() <= idx {
            self.files.resize_with(idx + 1, || None);
            self.cloexec.resize(idx + 1, false);
        }
    }

    fn alloc_fd(&mut self, file: Arc<File>) -> KResult<i32> {
        self.alloc_fd_min(file, 0)
    }

    /// First-fit allocate at fd >= `min`. Backs `fcntl F_DUPFD(arg)`.
    fn alloc_fd_min(&mut self, file: Arc<File>, min: usize) -> KResult<i32> {
        if self.files.len() > min {
            for (i, slot) in self.files.iter_mut().enumerate().skip(min) {
                if slot.is_none() {
                    *slot = Some(file);
                    self.cloexec[i] = false;
                    return Ok(i as i32);
                }
            }
        }
        let start = core::cmp::max(self.files.len(), min);
        if start >= FD_TABLE_MAX {
            return Err(VfsError::Emfile);
        }
        self.ensure_capacity(start);
        self.files[start] = Some(file);
        self.cloexec[start] = false;
        Ok(start as i32)
    }
}

/// Per-process FD table. Cloned via `Arc` for `CLONE_FILES`.
pub struct FdTable {
    inner: Spinlock<FdTableInner, FdTableClass>,
}

impl FdTable {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(FdTableInner {
            files: Vec::new(),
            cloexec: Vec::new(),
        }) }
    }

    /// Number of currently-allocated FDs (counting holes).
    /// # C: O(N)
    pub fn count(&self) -> usize {
        self.inner.lock().files.iter().filter(|s| s.is_some()).count()
    }

    /// Snapshot of live fd indices in ascending order. Used by
    /// procfs `/proc/<pid>/fd` enumeration per `19§4`.
    /// # C: O(N)
    pub fn live_fds(&self) -> Vec<i32> {
        let g = self.inner.lock();
        let mut v = Vec::with_capacity(g.files.len());
        for (i, s) in g.files.iter().enumerate() {
            if s.is_some() { v.push(i as i32); }
        }
        v
    }

    /// Install `file` at the lowest free fd; returns the fd number.
    /// # C: O(N)
    pub fn alloc(&self, file: Arc<File>) -> KResult<i32> {
        self.inner.lock().alloc_fd(file)
    }

    /// Snapshot the file at `fd`, or `Err(Ebadf)`.
    /// # C: O(1)
    pub fn get(&self, fd: i32) -> KResult<Arc<File>> {
        let g = self.inner.lock();
        if fd < 0 { return Err(VfsError::Ebadf); }
        let i = fd as usize;
        match g.files.get(i).and_then(|s| s.clone()) {
            Some(f) => Ok(f),
            None    => Err(VfsError::Ebadf),
        }
    }

    /// `close(2)` — clear the slot. Returns `Err(Ebadf)` if not open.
    /// # C: O(1)
    pub fn close(&self, fd: i32) -> KResult<()> {
        let mut g = self.inner.lock();
        if fd < 0 { return Err(VfsError::Ebadf); }
        let i = fd as usize;
        match g.files.get_mut(i) {
            Some(slot) if slot.is_some() => {
                *slot = None;
                g.cloexec[i] = false;
                Ok(())
            }
            _ => Err(VfsError::Ebadf),
        }
    }

    /// `dup(2)` — install the same `Arc<File>` at the lowest free fd.
    /// # C: O(N)
    pub fn dup(&self, fd: i32) -> KResult<i32> {
        let f = self.get(fd)?;
        self.alloc(f)
    }

    /// `fcntl F_DUPFD(fd, arg)` — install the same `Arc<File>` at the
    /// lowest free fd >= `min`. F_DUPFD_CLOEXEC sets cloexec on top.
    /// # C: O(N)
    pub fn dup_min(&self, fd: i32, min: i32) -> KResult<i32> {
        if min < 0 { return Err(VfsError::Einval); }
        let f = self.get(fd)?;
        self.inner.lock().alloc_fd_min(f, min as usize)
    }

    /// `dup2(2)` — install at exactly `new_fd`, closing whatever was
    /// there. `old_fd == new_fd` is an Ebadf-aware no-op per POSIX.
    /// # C: O(N)
    pub fn dup2(&self, old_fd: i32, new_fd: i32) -> KResult<i32> {
        if old_fd < 0 || new_fd < 0 || (new_fd as usize) >= FD_TABLE_MAX {
            return Err(VfsError::Ebadf);
        }
        let f = self.get(old_fd)?;
        if old_fd == new_fd { return Ok(new_fd); }
        let mut g = self.inner.lock();
        g.ensure_capacity(new_fd as usize);
        g.files[new_fd as usize]   = Some(f);
        g.cloexec[new_fd as usize] = false;
        Ok(new_fd)
    }

    /// Mark / clear the FD_CLOEXEC bit. `Err(Ebadf)` if `fd` is not open.
    /// # C: O(1)
    pub fn set_cloexec(&self, fd: i32, on: bool) -> KResult<()> {
        if fd < 0 { return Err(VfsError::Ebadf); }
        let mut g = self.inner.lock();
        let i = fd as usize;
        match g.files.get(i) {
            Some(Some(_)) => { g.cloexec[i] = on; Ok(()) }
            _ => Err(VfsError::Ebadf),
        }
    }

    /// # C: O(1)
    pub fn cloexec(&self, fd: i32) -> KResult<bool> {
        if fd < 0 { return Err(VfsError::Ebadf); }
        let g = self.inner.lock();
        let i = fd as usize;
        match g.files.get(i) {
            Some(Some(_)) => Ok(g.cloexec[i]),
            _ => Err(VfsError::Ebadf),
        }
    }

    /// `fork(2)` semantics — produce a new `FdTable` whose entries
    /// are Arc-clones of the parent's. Subsequent close/dup/etc.
    /// in either table don't disturb the other (the underlying
    /// `Arc<File>` is still shared, which matches POSIX: parent
    /// and child share the open-file description but not the
    /// fd-table slots).
    /// # C: O(N)
    pub fn fork_clone(&self) -> Self {
        let g = self.inner.lock();
        Self { inner: Spinlock::new(FdTableInner {
            files:   g.files.clone(),
            cloexec: g.cloexec.clone(),
        }) }
    }

    /// `execve` semantics: drop every FD with FD_CLOEXEC set.
    /// # C: O(N)
    pub fn close_on_exec(&self) {
        let mut g = self.inner.lock();
        let len = g.files.len();
        for i in 0..len {
            if g.cloexec.get(i).copied().unwrap_or(false) {
                g.files[i] = None;
            }
        }
        for v in g.cloexec.iter_mut() { *v = false; }
    }
}

impl Default for FdTable {
    fn default() -> Self { Self::new() }
}
