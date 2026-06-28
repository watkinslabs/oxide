// Per-process FD table per `16§5`. `files: Vec<Option<Arc<File>>>` (the
// file-pointer array, Linux `fdtable->fd[]`) plus two word-packed
// bitmaps — `open_fds` (1 = slot allocated, Linux `open_fds`) and
// `cloexec` (1 = FD_CLOEXEC, Linux `close_on_exec`) — all under a single
// per-process spinlock (class `FdTable`, `06§3.6`). Shared via
// `CLONE_FILES` (`Arc<FdTable>`).
//
// Free-fd search scans `open_fds` a word (64 fds) at a time
// (`trailing_zeros`), O(N/64), instead of a per-slot linear scan.
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

/// Bits per bitmap word.
const WORD_BITS: usize = 64;

#[inline]
fn word_idx(fd: usize) -> usize { fd / WORD_BITS }
#[inline]
fn bit_mask(fd: usize) -> u64 { 1u64 << (fd % WORD_BITS) }

#[derive(Default)]
struct FdTableInner {
    files:    Vec<Option<Arc<File>>>,
    /// 1 = fd slot allocated (Linux `open_fds`).
    open_fds: Vec<u64>,
    /// 1 = FD_CLOEXEC set on the fd (Linux `close_on_exec`).
    cloexec:  Vec<u64>,
}

impl FdTableInner {
    fn ensure_capacity(&mut self, idx: usize) {
        if self.files.len() <= idx {
            self.files.resize_with(idx + 1, || None);
        }
        let words = word_idx(idx) + 1;
        if self.open_fds.len() < words {
            self.open_fds.resize(words, 0);
            self.cloexec.resize(words, 0);
        }
    }

    #[inline]
    fn is_open(&self, fd: usize) -> bool {
        self.open_fds.get(word_idx(fd)).is_some_and(|w| w & bit_mask(fd) != 0)
    }

    #[inline]
    fn set_open(&mut self, fd: usize, on: bool) {
        let w = &mut self.open_fds[word_idx(fd)];
        if on { *w |= bit_mask(fd); } else { *w &= !bit_mask(fd); }
    }

    #[inline]
    fn set_cloexec_bit(&mut self, fd: usize, on: bool) {
        let w = &mut self.cloexec[word_idx(fd)];
        if on { *w |= bit_mask(fd); } else { *w &= !bit_mask(fd); }
    }

    #[inline]
    fn get_cloexec(&self, fd: usize) -> bool {
        self.cloexec.get(word_idx(fd)).is_some_and(|w| w & bit_mask(fd) != 0)
    }

    fn alloc_fd(&mut self, file: Arc<File>) -> KResult<i32> {
        self.alloc_fd_min(file, 0)
    }

    /// First-fit allocate at the lowest free fd >= `min`. Backs
    /// `fcntl F_DUPFD(arg)`. Scans `open_fds` a word at a time.
    fn alloc_fd_min(&mut self, file: Arc<File>, min: usize) -> KResult<i32> {
        let mut fd = min;
        loop {
            if fd >= FD_TABLE_MAX { return Err(VfsError::Emfile); }
            let wi = word_idx(fd);
            if wi >= self.open_fds.len() { break; } // beyond bitmap → free
            let word = self.open_fds[wi];
            if word == u64::MAX { fd = (wi + 1) * WORD_BITS; continue; }
            // Zero bits in `word` at positions >= the start bit.
            let start = fd % WORD_BITS;
            let below = if start == 0 { 0 } else { (1u64 << start) - 1 };
            let cand = !word & !below;
            if cand == 0 { fd = (wi + 1) * WORD_BITS; continue; }
            fd = wi * WORD_BITS + cand.trailing_zeros() as usize;
            break;
        }
        if fd >= FD_TABLE_MAX { return Err(VfsError::Emfile); }
        self.ensure_capacity(fd);
        self.files[fd] = Some(file);
        self.set_open(fd, true);
        self.set_cloexec_bit(fd, false);
        Ok(fd as i32)
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
            open_fds: Vec::new(),
            cloexec: Vec::new(),
        }) }
    }

    /// Number of currently-allocated FDs (counting holes).
    /// # C: O(N/64)
    pub fn count(&self) -> usize {
        self.inner.lock().open_fds.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Snapshot of live fd indices in ascending order. Used by
    /// procfs `/proc/<pid>/fd` enumeration per `19§4`.
    /// # C: O(N/64 + open_fds)
    pub fn live_fds(&self) -> Vec<i32> {
        let g = self.inner.lock();
        let mut v = Vec::with_capacity(g.open_fds.iter().map(|w| w.count_ones() as usize).sum());
        for (wi, word) in g.open_fds.iter().copied().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let fd = wi * WORD_BITS + b;
                if fd < g.files.len() && g.files[fd].is_some() {
                    v.push(fd as i32);
                }
            }
        }
        v
    }

    /// Install `file` at the lowest free fd; returns the fd number.
    /// # C: O(N/64)
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
    /// Fires the per-close flush hook on the removed File before its
    /// Arc reference is dropped (Linux `filp_close`).
    /// # C: O(1)
    pub fn close(&self, fd: i32) -> KResult<()> {
        if fd < 0 { return Err(VfsError::Ebadf); }
        let i = fd as usize;
        let removed = {
            let mut g = self.inner.lock();
            match g.files.get_mut(i) {
                Some(slot) if slot.is_some() => {
                    let f = slot.take();
                    g.set_open(i, false);
                    g.set_cloexec_bit(i, false);
                    f
                }
                _ => return Err(VfsError::Ebadf),
            }
        };
        // Flush OUTSIDE the table lock — inode flush may touch other locks.
        if let Some(f) = removed { f.flush(); }
        Ok(())
    }

    /// `dup(2)` — install the same `Arc<File>` at the lowest free fd.
    /// The new fd starts with FD_CLOEXEC clear (independent fd flag),
    /// sharing the open file description (incl. `mnt_id`/position).
    /// # C: O(N/64)
    pub fn dup(&self, fd: i32) -> KResult<i32> {
        let f = self.get(fd)?;
        crate::file::fire_clone_hook(&f);
        self.alloc(f)
    }

    /// `fcntl F_DUPFD(fd, arg)` — install the same `Arc<File>` at the
    /// lowest free fd >= `min`. F_DUPFD_CLOEXEC sets cloexec on top.
    /// # C: O(N/64)
    pub fn dup_min(&self, fd: i32, min: i32) -> KResult<i32> {
        if min < 0 { return Err(VfsError::Einval); }
        let f = self.get(fd)?;
        crate::file::fire_clone_hook(&f);
        self.inner.lock().alloc_fd_min(f, min as usize)
    }

    /// `dup2(2)` — install at exactly `new_fd`, closing whatever was
    /// there (and flushing it). `old_fd == new_fd` is an Ebadf-aware
    /// no-op per POSIX.
    /// # C: O(1) + close
    pub fn dup2(&self, old_fd: i32, new_fd: i32) -> KResult<i32> {
        if old_fd < 0 || new_fd < 0 || (new_fd as usize) >= FD_TABLE_MAX {
            return Err(VfsError::Ebadf);
        }
        let f = self.get(old_fd)?;
        if old_fd == new_fd { return Ok(new_fd); }
        crate::file::fire_clone_hook(&f);
        let nf = new_fd as usize;
        let replaced = {
            let mut g = self.inner.lock();
            g.ensure_capacity(nf);
            let old = g.files[nf].take();
            g.files[nf] = Some(f);
            g.set_open(nf, true);
            g.set_cloexec_bit(nf, false);
            old
        };
        if let Some(old) = replaced { old.flush(); }
        Ok(new_fd)
    }

    /// Mark / clear the FD_CLOEXEC bit. `Err(Ebadf)` if `fd` is not open.
    /// # C: O(1)
    pub fn set_cloexec(&self, fd: i32, on: bool) -> KResult<()> {
        if fd < 0 { return Err(VfsError::Ebadf); }
        let mut g = self.inner.lock();
        let i = fd as usize;
        if g.is_open(i) { g.set_cloexec_bit(i, on); Ok(()) } else { Err(VfsError::Ebadf) }
    }

    /// # C: O(1)
    pub fn cloexec(&self, fd: i32) -> KResult<bool> {
        if fd < 0 { return Err(VfsError::Ebadf); }
        let g = self.inner.lock();
        let i = fd as usize;
        if g.is_open(i) { Ok(g.get_cloexec(i)) } else { Err(VfsError::Ebadf) }
    }

    /// `fork(2)` semantics — produce a new `FdTable` whose entries
    /// are Arc-clones of the parent's, with both bitmaps copied.
    /// Subsequent close/dup/etc. in either table don't disturb the
    /// other (the underlying `Arc<File>` is still shared, which matches
    /// POSIX: parent and child share the open-file description but not
    /// the fd-table slots).
    /// # C: O(N)
    pub fn fork_clone(&self) -> Self {
        let g = self.inner.lock();
        // F205: fire the clone hook for every duplicated File reference.
        for slot in g.files.iter() {
            if let Some(f) = slot.as_ref() {
                crate::file::fire_clone_hook(f);
            }
        }
        Self { inner: Spinlock::new(FdTableInner {
            files:    g.files.clone(),
            open_fds: g.open_fds.clone(),
            cloexec:  g.cloexec.clone(),
        }) }
    }

    /// `execve` semantics: drop every FD with FD_CLOEXEC set, flushing
    /// each (Linux `filp_close` per cloexec fd). Iterates the cloexec
    /// bitmap a word at a time.
    /// # C: O(N/64 + closed)
    pub fn close_on_exec(&self) {
        let removed = {
            let mut g = self.inner.lock();
            let mut removed: Vec<Arc<File>> = Vec::new();
            for wi in 0..g.cloexec.len() {
                let mut bits = g.cloexec[wi];
                while bits != 0 {
                    let b = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    let fd = wi * WORD_BITS + b;
                    if let Some(f) = g.files.get_mut(fd).and_then(|s| s.take()) {
                        removed.push(f);
                    }
                    g.set_open(fd, false);
                }
                g.cloexec[wi] = 0;
            }
            removed
        };
        for f in removed { f.flush(); }
    }
}

impl Default for FdTable {
    fn default() -> Self { Self::new() }
}
