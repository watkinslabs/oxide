extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{FdTable as FdTableClass, Spinlock};

use crate::file::File;
use crate::types::{KResult, VfsError};

pub const FD_TABLE_MAX: usize = 1024;
pub(super) const WORD_BITS: usize = 64;

#[inline]
pub(super) fn word_idx(fd: usize) -> usize { fd / WORD_BITS }
#[inline]
pub(super) fn bit_mask(fd: usize) -> u64 { 1u64 << (fd % WORD_BITS) }

pub(super) fn sane_fdtable_words(open_fds: &[u64]) -> usize {
    for wi in (0..open_fds.len()).rev() {
        if open_fds[wi] != 0 { return wi + 1; }
    }
    0
}

#[derive(Default)]
pub(super) struct FdTableInner {
    pub(super) files:    Vec<Option<Arc<File>>>,
    pub(super) open_fds: Vec<u64>,
    pub(super) cloexec:  Vec<u64>,
    pub(super) reserved: Vec<u64>,
}

impl FdTableInner {
    pub(super) fn ensure_capacity(&mut self, idx: usize) {
        if self.files.len() <= idx { self.files.resize_with(idx + 1, || None); }
        let words = word_idx(idx) + 1;
        if self.open_fds.len() < words {
            self.open_fds.resize(words, 0);
            self.cloexec.resize(words, 0);
            self.reserved.resize(words, 0);
        }
    }
    pub(super) fn is_open(&self, fd: usize) -> bool {
        self.open_fds.get(word_idx(fd)).is_some_and(|w| w & bit_mask(fd) != 0)
    }
    pub(super) fn set_open(&mut self, fd: usize, on: bool) {
        let w = &mut self.open_fds[word_idx(fd)];
        if on { *w |= bit_mask(fd); } else { *w &= !bit_mask(fd); }
    }
    pub(super) fn set_cloexec_bit(&mut self, fd: usize, on: bool) {
        let w = &mut self.cloexec[word_idx(fd)];
        if on { *w |= bit_mask(fd); } else { *w &= !bit_mask(fd); }
    }
    pub(super) fn is_reserved(&self, fd: usize) -> bool {
        self.reserved.get(word_idx(fd)).is_some_and(|word| word & bit_mask(fd) != 0)
    }
    pub(super) fn set_reserved(&mut self, fd: usize, on: bool) {
        let word = &mut self.reserved[word_idx(fd)];
        if on { *word |= bit_mask(fd); } else { *word &= !bit_mask(fd); }
    }
    pub(super) fn get_cloexec(&self, fd: usize) -> bool {
        self.cloexec.get(word_idx(fd)).is_some_and(|w| w & bit_mask(fd) != 0)
    }
    pub(super) fn alloc_fd(&mut self, file: Arc<File>) -> KResult<i32> { self.alloc_fd_below(file, 0, FD_TABLE_MAX) }
    pub(super) fn find_free_fd(&self, min: usize, max: usize) -> KResult<usize> {
        let mut fd = min;
        loop {
            if fd >= max { return Err(VfsError::Emfile); }
            let wi = word_idx(fd);
            if wi >= self.open_fds.len() { break; }
            let word = self.open_fds[wi];
            if word == u64::MAX { fd = (wi + 1) * WORD_BITS; continue; }
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
    pub(super) fn alloc_fd_flags_below(&mut self, file: Arc<File>, min: usize, max: usize,
                                       cloexec: bool) -> KResult<i32> {
        let fd = self.find_free_fd(min, max)?;
        self.ensure_capacity(fd);
        self.files[fd] = Some(file);
        self.set_open(fd, true);
        self.set_cloexec_bit(fd, cloexec);
        self.set_reserved(fd, false);
        Ok(fd as i32)
    }
    pub(super) fn alloc_fd_below(&mut self, file: Arc<File>, min: usize, max: usize) -> KResult<i32> {
        self.alloc_fd_flags_below(file, min, max, false)
    }
    pub(super) fn reserve_fd_below(&mut self, min: usize, max: usize, cloexec: bool) -> KResult<i32> {
        let fd = self.find_free_fd(min, max)?;
        self.ensure_capacity(fd);
        self.files[fd] = None;
        self.set_open(fd, true);
        self.set_cloexec_bit(fd, cloexec);
        self.set_reserved(fd, true);
        Ok(fd as i32)
    }
}

pub struct FdTable {
    pub(super) inner: Spinlock<FdTableInner, FdTableClass>,
}

impl FdTable {
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(FdTableInner {
            files: Vec::new(), open_fds: Vec::new(), cloexec: Vec::new(), reserved: Vec::new(),
        }) }
    }
}

impl Default for FdTable {
    fn default() -> Self { Self::new() }
}

impl Drop for FdTable {
    fn drop(&mut self) {
        let files = {
            let mut inner = self.inner.lock();
            core::mem::take(&mut inner.files)
        };
        // Linux `put_files_struct` → `close_files` → `filp_close(file, files)`
        // for every open descriptor. The POSIX record locks this table owns die
        // with it, so a process exiting while holding an `fcntl(F_SETLK)` byte
        // range must release it here — otherwise a peer parked in
        // `fcntl(F_SETLKW)` waits on a holder that no longer exists, forever.
        let owner = super::close::files_owner(self);
        for file in files.into_iter().flatten() {
            let _ = super::close::filp_close(owner, file);
        }
    }
}
