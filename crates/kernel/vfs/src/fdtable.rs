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
use crate::types::{KResult, OpenFlags, VfsError};

/// Soft limit on FDs per process. Linux's default `RLIMIT_NOFILE` is
/// 1024; raise to 64 KiB once cgroup-tracked rlimits land.
pub const FD_TABLE_MAX: usize = 1024;

/// Bits per bitmap word.
const WORD_BITS: usize = 64;

#[inline]
fn word_idx(fd: usize) -> usize { fd / WORD_BITS }
#[inline]
fn bit_mask(fd: usize) -> u64 { 1u64 << (fd % WORD_BITS) }

/// Linux `sane_fdtable_size` at word granularity: number of `open_fds` WORDS a
/// forked child needs to cover the parent's currently-open fds — the highest
/// set-bit word index + 1 (`u64`-word aligned, mirroring `ALIGN(count,
/// BITS_PER_LONG)`). `0` when no fd is open, so a parent that opened then
/// CLOSED a high fd hands the child a SMALL table — the shrink Linux performs
/// in `dup_fd`, vs our live table that otherwise only ever grows.
/// # C: O(N/64)
fn sane_fdtable_words(open_fds: &[u64]) -> usize {
    for wi in (0..open_fds.len()).rev() {
        if open_fds[wi] != 0 { return wi + 1; }
    }
    0
}

#[derive(Default)]
struct FdTableInner {
    files:    Vec<Option<Arc<File>>>,
    /// 1 = fd slot allocated (Linux `open_fds`).
    open_fds: Vec<u64>,
    /// 1 = FD_CLOEXEC set on the fd (Linux `close_on_exec`).
    cloexec:  Vec<u64>,
}

impl FdTableInner {
    /// Grow the `fd[]` array + bitmaps to cover slot `idx`, holding the
    /// per-process `FdTable` spinlock across the realloc.
    ///
    /// D33: the realloc-under-lock is BOUNDED, unlike Linux's `expand_fdtable`
    /// (which drops `files->file_lock`, allocates a fresh power-of-two `fdtable`
    /// up to `sysctl_nr_open` ≈ 1M fds via RCU, then re-acquires + publishes).
    /// Here `idx` is always `< FD_TABLE_MAX` (1024) — every caller reaches this
    /// only AFTER `find_free_fd`/range checks have rejected fds `>= FD_TABLE_MAX`
    /// — so the worst-case growth is a one-shot copy of 1024 `Option<Arc<File>>`
    /// (8 KiB of pointers) + 16 `u64` bitmap words. A bounded ≤8 KiB memcpy
    /// under a non-sleeping spinlock is acceptable; it does NOT need Linux's
    /// drop-lock / RCU-publish dance, which exists precisely because Linux's
    /// table is unbounded. Should `FD_TABLE_MAX` ever be raised toward Linux's
    /// `nr_open`, revisit this (move to an `Arc`-published swap, like the
    /// `fork_clone` whole-table swap already does). # C: O(idx) one-shot copy
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
        self.alloc_fd_below(file, 0, FD_TABLE_MAX)
    }

    /// First-fit allocate at the lowest free fd >= `min`, ceiling at
    /// the hard `FD_TABLE_MAX`. Backs `fcntl F_DUPFD(arg)`.
    fn alloc_fd_min(&mut self, file: Arc<File>, min: usize) -> KResult<i32> {
        self.alloc_fd_below(file, min, FD_TABLE_MAX)
    }

    /// Lowest free fd index in `[min, max)` (i.e. the lowest fd whose
    /// `open_fds` bit is clear), or `Emfile` if none below `max`. Scans
    /// `open_fds` a word (64 fds) at a time via `trailing_zeros`. Pure
    /// query — does not mutate; callers commit with `set_open`.
    fn find_free_fd(&self, min: usize, max: usize) -> KResult<usize> {
        let mut fd = min;
        loop {
            if fd >= max { return Err(VfsError::Emfile); }
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
        if fd >= max { return Err(VfsError::Emfile); }
        Ok(fd)
    }

    /// First-fit allocate at the lowest free fd in `[min, max)`. `max`
    /// is the effective ceiling = min(RLIMIT_NOFILE soft, FD_TABLE_MAX);
    /// reaching it → `Emfile` (Linux `alloc_fd` against
    /// `rlimit(RLIMIT_NOFILE)`). Installs `file` in one shot.
    fn alloc_fd_below(&mut self, file: Arc<File>, min: usize, max: usize) -> KResult<i32> {
        let fd = self.find_free_fd(min, max)?;
        self.ensure_capacity(fd);
        self.files[fd] = Some(file);
        self.set_open(fd, true);
        self.set_cloexec_bit(fd, false);
        Ok(fd as i32)
    }

    /// Reserve (but do not install) the lowest free fd in `[min, max)`:
    /// mark the `open_fds` bit so no concurrent allocation can hand out
    /// the same fd, leave `files[fd] == None`, and set FD_CLOEXEC per
    /// `cloexec`. Linux `alloc_fd`/`get_unused_fd_flags` first half; the
    /// matching `fd_install` publishes the file, `put_unused_fd` rolls
    /// the reservation back on the open error path.
    fn reserve_fd_below(&mut self, min: usize, max: usize, cloexec: bool) -> KResult<i32> {
        let fd = self.find_free_fd(min, max)?;
        self.ensure_capacity(fd);
        self.files[fd] = None; // reserved, awaiting fd_install
        self.set_open(fd, true);
        self.set_cloexec_bit(fd, cloexec);
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

    /// Backing `fd[]` slot capacity (Linux `fdtable->max_fds`) — the number of
    /// fd slots allocated, NOT the number open. Grows on `alloc`/`dup2` and
    /// SHRINKS on `fork_clone` (Linux `sane_fdtable_size`); exposed so the
    /// shrink-on-fork right-sizing is observable.
    /// # C: O(1)
    pub fn capacity(&self) -> usize { self.inner.lock().files.len() }

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

    /// Install `file` at the lowest free fd below `limit` (the caller's
    /// `RLIMIT_NOFILE` soft limit), clamped to the hard `FD_TABLE_MAX`
    /// table ceiling. Reaching the effective ceiling → `Emfile` (Linux
    /// `__alloc_fd(files, 0, rlimit(RLIMIT_NOFILE), flags)`). A `limit`
    /// of 0 always yields `Emfile` (no fd is permitted).
    /// # C: O(N/64)
    pub fn alloc_limit(&self, file: Arc<File>, limit: usize) -> KResult<i32> {
        let max = if limit < FD_TABLE_MAX { limit } else { FD_TABLE_MAX };
        self.inner.lock().alloc_fd_below(file, 0, max)
    }

    /// Reserve the lowest free fd below `limit` (the caller's
    /// `RLIMIT_NOFILE` soft limit, clamped to `FD_TABLE_MAX`) without
    /// installing a file, setting FD_CLOEXEC from `O_CLOEXEC` in `flags`
    /// atomically with the reservation. Linux `get_unused_fd_flags`:
    /// the returned fd's `open_fds` bit is set (so a concurrent
    /// `CLONE_FILES` sibling's `alloc`/reserve skips it), but `files[fd]`
    /// stays `None` until `fd_install`, so `get(fd)` still yields `Ebadf`
    /// in the reserved window. The open-path contract is reserve →
    /// build the `File` (may sleep in path resolution) → `fd_install` on
    /// success / `put_unused_fd` on error. Only `O_CLOEXEC` is consulted;
    /// other flag bits belong to the open file description, not the fd.
    /// # C: O(N/64)
    pub fn get_unused_fd_flags(&self, flags: OpenFlags, limit: usize) -> KResult<i32> {
        let max = if limit < FD_TABLE_MAX { limit } else { FD_TABLE_MAX };
        let cloexec = flags.contains(OpenFlags::O_CLOEXEC);
        self.inner.lock().reserve_fd_below(0, max, cloexec)
    }

    /// Publish `file` at a fd previously handed out by
    /// `get_unused_fd_flags`, completing the two-phase install (Linux
    /// `fd_install`). The reservation's FD_CLOEXEC bit (set at reserve
    /// time) is preserved. Infallible by contract: the caller must pass
    /// a reserved-but-uninstalled fd; misuse (unreserved slot or an fd
    /// already carrying a file) is a kernel bug.
    /// # C: O(1)
    pub fn fd_install(&self, fd: i32, file: Arc<File>) {
        hal::kassert!(fd >= 0, "fd_install: fd from get_unused_fd_flags is never negative");
        let i = fd as usize;
        let mut g = self.inner.lock();
        hal::kassert!(g.is_open(i), "fd_install: target fd must be a live reservation");
        hal::kassert!(g.files.get(i).is_some_and(|s| s.is_none()),
            "fd_install: reserved slot must be empty before publishing the file");
        g.files[i] = Some(file);
    }

    /// Release a reservation from `get_unused_fd_flags` whose `fd_install`
    /// never happened (the open failed): clear the `open_fds` and cloexec
    /// bits so the fd is free again (Linux `put_unused_fd`). The slot is
    /// already `None`, so no file is dropped; calling this on an
    /// installed fd would clear the bitmap without flushing, so it is
    /// reserved for the error path only.
    /// # C: O(1)
    pub fn put_unused_fd(&self, fd: i32) {
        if fd < 0 { return; }
        let i = fd as usize;
        let mut g = self.inner.lock();
        if g.is_open(i) {
            g.set_open(i, false);
            g.set_cloexec_bit(i, false);
        }
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
    /// `oldfd` is validated first (bad/negative → Ebadf, matching the
    /// syscall-layer fdget); then `min` is range-checked: negative OR
    /// `>= FD_TABLE_MAX` (the RLIMIT_NOFILE ceiling) → Einval, NOT
    /// Emfile — Linux `do_fcntl` F_DUPFD returns EINVAL for an `arg`
    /// outside the allowed fd range before attempting allocation.
    /// # C: O(N/64)
    pub fn dup_min(&self, fd: i32, min: i32) -> KResult<i32> {
        let f = self.get(fd)?;
        if min < 0 || min as usize >= FD_TABLE_MAX { return Err(VfsError::Einval); }
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

    /// `dup3(2)` — install `old_fd` at exactly `new_fd`, closing (and
    /// flushing) whatever was there, with FD_CLOEXEC set per `flags`.
    /// Differs from `dup2` on two points Linux `ksys_dup3` enforces:
    ///   * `old_fd == new_fd` → `Einval` (NOT a no-op — `dup2` returns
    ///     `new_fd`, `dup3` rejects); checked before fd validity, so an
    ///     equal-but-bad pair is `Einval`, not `Ebadf`.
    ///   * the new fd's FD_CLOEXEC is set from `O_CLOEXEC` in `flags`
    ///     atomically with the install (no follow-up `set_cloexec`).
    /// Flag bits other than `O_CLOEXEC` → `Einval`. Order mirrors
    /// `ksys_dup3`: bad flags (Einval) → equal fds (Einval) → `new_fd`
    /// out of range (Ebadf) → `old_fd` invalid (Ebadf).
    /// # C: O(1) + close
    pub fn dup3(&self, old_fd: i32, new_fd: i32, flags: OpenFlags) -> KResult<i32> {
        if flags.bits() & !OpenFlags::O_CLOEXEC.bits() != 0 { return Err(VfsError::Einval); }
        if old_fd == new_fd { return Err(VfsError::Einval); }
        if new_fd < 0 || (new_fd as usize) >= FD_TABLE_MAX { return Err(VfsError::Ebadf); }
        let f = self.get(old_fd)?;
        crate::file::fire_clone_hook(&f);
        let cloexec = flags.contains(OpenFlags::O_CLOEXEC);
        let nf = new_fd as usize;
        let replaced = {
            let mut g = self.inner.lock();
            g.ensure_capacity(nf);
            let old = g.files[nf].take();
            g.files[nf] = Some(f);
            g.set_open(nf, true);
            g.set_cloexec_bit(nf, cloexec);
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

    /// `fork(2)` semantics — produce a new `FdTable` whose entries are
    /// Arc-clones of the parent's. Subsequent close/dup/etc. in either table
    /// don't disturb the other (the underlying `Arc<File>` is still shared,
    /// which matches POSIX: parent and child share the open-file description
    /// but not the fd-table slots).
    ///
    /// The child table is RIGHT-SIZED to the parent's currently-open fds
    /// (Linux `dup_fd` → `sane_fdtable_size`), NOT to the parent's high-water
    /// capacity: a parent that opened fd 900 then closed it hands the child a
    /// 64-slot table, not a 1024-slot one. This is the only path that produces
    /// a SMALLER table — the live table (`ensure_capacity`) only ever grows.
    /// The whole-table swap under `Arc` (and spinlock-guarded live mutation) is
    /// the no_std substitute for Linux's RCU-published `fdtable` replacement.
    /// # C: O(open fds)
    pub fn fork_clone(&self) -> Self {
        let g = self.inner.lock();
        let words = sane_fdtable_words(&g.open_fds);
        let nfiles = words * WORD_BITS;
        let mut files: Vec<Option<Arc<File>>> = Vec::with_capacity(nfiles);
        for slot in g.files.iter().take(nfiles) {
            // F205: fire the clone hook for every duplicated File reference.
            if let Some(f) = slot.as_ref() { crate::file::fire_clone_hook(f); }
            // D38: f_count coupling — `slot.clone()` is `Option<Arc<File>>::clone`,
            // i.e. `Arc::clone` of the SAME open file description, bumping its
            // `f_count` (the `Arc` strong count). Parent and child fd slots then
            // point at ONE shared `File` (shared cursor / flags per POSIX), and
            // the backend `->release` runs only when the LAST of the two drops.
            // No transmute-clone, no fresh `File`: identity is preserved.
            files.push(slot.clone());
        }
        files.resize_with(nfiles, || None); // pad to the word-aligned slot count
        Self { inner: Spinlock::new(FdTableInner {
            files,
            open_fds: g.open_fds[..words].to_vec(),
            cloexec:  g.cloexec[..words].to_vec(),
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

    /// `close_range(2)` (Linux `__range_close`) — over the inclusive fd
    /// range `[first, last]`, close every open fd, OR — when
    /// `cloexec_only` (CLOSE_RANGE_CLOEXEC) — set FD_CLOEXEC on each
    /// instead of closing. `first`/`last` are `u32` to match the uapi
    /// (a `last` of `u32::MAX` means "to the table end"); the syscall
    /// layer rejects `first > last` (Einval), so here it is a no-op.
    /// Scans the `open_fds` bitmap a word at a time, starting at the
    /// word holding `first`; closed Files are flushed outside the table
    /// lock (Linux `filp_close` per fd). The bit walk reads a per-word
    /// snapshot, so clearing `open_fds` mid-walk does not skip fds.
    /// # C: O(N/64 + closed)
    pub fn close_range(&self, first: u32, last: u32, cloexec_only: bool) {
        let removed = {
            let mut g = self.inner.lock();
            let mut removed: Vec<Arc<File>> = Vec::new();
            let start_word = word_idx(first as usize);
            for wi in start_word..g.open_fds.len() {
                let mut bits = g.open_fds[wi];
                while bits != 0 {
                    let b = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    let fd = wi * WORD_BITS + b;
                    if (fd as u64) < first as u64 || (fd as u64) > last as u64 { continue; }
                    if cloexec_only {
                        g.set_cloexec_bit(fd, true);
                    } else {
                        if let Some(f) = g.files.get_mut(fd).and_then(|s| s.take()) {
                            removed.push(f);
                        }
                        g.set_open(fd, false);
                        g.set_cloexec_bit(fd, false);
                    }
                }
            }
            removed
        };
        for f in removed { f.flush(); }
    }
}

impl Default for FdTable {
    fn default() -> Self { Self::new() }
}
