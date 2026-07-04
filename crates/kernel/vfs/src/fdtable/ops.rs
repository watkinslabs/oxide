extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::file::File;
use crate::types::{KResult, OpenFlags, VfsError};

use super::model::{FD_TABLE_MAX, FdTable, FdTableInner, WORD_BITS, sane_fdtable_words, word_idx};

impl FdTable {
    pub fn count(&self) -> usize {
        self.inner.lock().open_fds.iter().map(|w| w.count_ones() as usize).sum()
    }
    pub fn capacity(&self) -> usize { self.inner.lock().files.len() }
    pub fn live_fds(&self) -> Vec<i32> {
        let g = self.inner.lock();
        let mut v = Vec::with_capacity(g.open_fds.iter().map(|w| w.count_ones() as usize).sum());
        for (wi, word) in g.open_fds.iter().copied().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let b = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let fd = wi * WORD_BITS + b;
                if fd < g.files.len() && g.files[fd].is_some() { v.push(fd as i32); }
            }
        }
        v
    }
    pub fn alloc(&self, file: Arc<File>) -> KResult<i32> { self.inner.lock().alloc_fd(file) }
    pub fn alloc_limit(&self, file: Arc<File>, limit: usize) -> KResult<i32> {
        let max = if limit < FD_TABLE_MAX { limit } else { FD_TABLE_MAX };
        self.inner.lock().alloc_fd_below(file, 0, max)
    }
    pub fn get_unused_fd_flags(&self, flags: OpenFlags, limit: usize) -> KResult<i32> {
        let max = if limit < FD_TABLE_MAX { limit } else { FD_TABLE_MAX };
        let cloexec = flags.contains(OpenFlags::O_CLOEXEC);
        self.inner.lock().reserve_fd_below(0, max, cloexec)
    }
    pub fn fd_install(&self, fd: i32, file: Arc<File>) {
        hal::kassert!(fd >= 0, "fd_install: fd from get_unused_fd_flags is never negative");
        let i = fd as usize;
        let mut g = self.inner.lock();
        hal::kassert!(g.is_open(i), "fd_install: target fd must be a live reservation");
        hal::kassert!(g.files.get(i).is_some_and(|s| s.is_none()), "fd_install: reserved slot must be empty before publishing the file");
        g.files[i] = Some(file);
    }
    pub fn put_unused_fd(&self, fd: i32) {
        if fd < 0 { return; }
        let i = fd as usize;
        let mut g = self.inner.lock();
        if g.is_open(i) {
            g.set_open(i, false);
            g.set_cloexec_bit(i, false);
        }
    }
    pub fn get(&self, fd: i32) -> KResult<Arc<File>> {
        let g = self.inner.lock();
        if fd < 0 { return Err(VfsError::Ebadf); }
        let i = fd as usize;
        match g.files.get(i).and_then(|s| s.clone()) {
            Some(f) => Ok(f),
            None => Err(VfsError::Ebadf),
        }
    }
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
        if let Some(f) = removed { f.flush(); }
        Ok(())
    }
    pub fn dup(&self, fd: i32) -> KResult<i32> {
        let f = self.get(fd)?;
        crate::file::fire_clone_hook(&f);
        self.alloc(f)
    }
    pub fn dup_min(&self, fd: i32, min: i32) -> KResult<i32> {
        let f = self.get(fd)?;
        if min < 0 || min as usize >= FD_TABLE_MAX { return Err(VfsError::Einval); }
        crate::file::fire_clone_hook(&f);
        self.inner.lock().alloc_fd_min(f, min as usize)
    }
    pub fn dup2(&self, old_fd: i32, new_fd: i32) -> KResult<i32> {
        if old_fd < 0 || new_fd < 0 || (new_fd as usize) >= FD_TABLE_MAX { return Err(VfsError::Ebadf); }
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
    pub fn set_cloexec(&self, fd: i32, on: bool) -> KResult<()> {
        if fd < 0 { return Err(VfsError::Ebadf); }
        let mut g = self.inner.lock();
        let i = fd as usize;
        if g.is_open(i) { g.set_cloexec_bit(i, on); Ok(()) } else { Err(VfsError::Ebadf) }
    }
    pub fn cloexec(&self, fd: i32) -> KResult<bool> {
        if fd < 0 { return Err(VfsError::Ebadf); }
        let g = self.inner.lock();
        let i = fd as usize;
        if g.is_open(i) { Ok(g.get_cloexec(i)) } else { Err(VfsError::Ebadf) }
    }
    pub fn fork_clone(&self) -> Self {
        let g = self.inner.lock();
        let words = sane_fdtable_words(&g.open_fds);
        let nfiles = words * WORD_BITS;
        let mut files: Vec<Option<Arc<File>>> = Vec::with_capacity(nfiles);
        for slot in g.files.iter().take(nfiles) {
            if let Some(f) = slot.as_ref() { crate::file::fire_clone_hook(f); }
            files.push(slot.clone());
        }
        files.resize_with(nfiles, || None);
        Self { inner: sync::Spinlock::new(FdTableInner {
            files,
            open_fds: g.open_fds[..words].to_vec(),
            cloexec: g.cloexec[..words].to_vec(),
        }) }
    }
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
                    if let Some(f) = g.files.get_mut(fd).and_then(|s| s.take()) { removed.push(f); }
                    g.set_open(fd, false);
                }
                g.cloexec[wi] = 0;
            }
            removed
        };
        for f in removed { f.flush(); }
    }
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
                        if let Some(f) = g.files.get_mut(fd).and_then(|s| s.take()) { removed.push(f); }
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
