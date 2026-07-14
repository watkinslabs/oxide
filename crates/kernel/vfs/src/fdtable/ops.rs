extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::file::File;
use crate::types::{KResult, OpenFlags, VfsError};

use super::model::{FD_TABLE_MAX, FdTable, FdTableInner, WORD_BITS, bit_mask, sane_fdtable_words, word_idx};

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
    /// Reserve, copy out, then publish one received file descriptor. # C: O(fd-table words + copyout)
    pub fn scm_install_fd<F>(&self, file: Arc<File>, flags: OpenFlags, limit: usize, copyout: F) -> KResult<i32>
    where F: FnOnce(i32) -> KResult<()> {
        let fd = self.get_unused_fd_flags(flags, limit)?;
        if let Err(e) = copyout(fd) {
            self.put_unused_fd(fd);
            return Err(e);
        }
        crate::file::fire_clone_hook(&file);
        self.fd_install(fd, file);
        Ok(fd)
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
        if g.is_open(i) && g.files.get(i).is_some_and(|slot| slot.is_none()) {
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
        match removed {
            Some(f) => {
                let result = f.flush();
                drop(f);
                super::fire_file_ref_drop_hook();
                result
            }
            None => Ok(()),
        }
    }
    pub fn dup(&self, fd: i32) -> KResult<i32> {
        self.dup_limit(fd, FD_TABLE_MAX)
    }
    pub fn dup_limit(&self, fd: i32, limit: usize) -> KResult<i32> {
        let f = self.get(fd)?;
        let n = self.alloc_limit(Arc::clone(&f), limit)?;
        crate::file::fire_clone_hook(&f);
        Ok(n)
    }
    pub fn dup_min(&self, fd: i32, min: i32) -> KResult<i32> {
        self.dup_min_limit(fd, min, FD_TABLE_MAX)
    }
    pub fn dup_min_limit(&self, fd: i32, min: i32, limit: usize) -> KResult<i32> {
        let f = self.get(fd)?;
        let max = if limit < FD_TABLE_MAX { limit } else { FD_TABLE_MAX };
        if min < 0 || min as usize >= max { return Err(VfsError::Einval); }
        let n = self.inner.lock().alloc_fd_below(Arc::clone(&f), min as usize, max)?;
        crate::file::fire_clone_hook(&f);
        Ok(n)
    }
    pub fn dup2(&self, old_fd: i32, new_fd: i32) -> KResult<i32> {
        self.dup2_limit(old_fd, new_fd, FD_TABLE_MAX)
    }
    pub fn dup2_limit(&self, old_fd: i32, new_fd: i32, limit: usize) -> KResult<i32> {
        if old_fd < 0 || new_fd < 0 || (new_fd as usize) >= FD_TABLE_MAX { return Err(VfsError::Ebadf); }
        if old_fd == new_fd {
            self.get(old_fd)?;
            return Ok(new_fd);
        }
        let max = if limit < FD_TABLE_MAX { limit } else { FD_TABLE_MAX };
        if (new_fd as usize) >= max { return Err(VfsError::Ebadf); }
        let f = self.get(old_fd)?;
        let nf = new_fd as usize;
        let replaced = {
            let mut g = self.inner.lock();
            g.ensure_capacity(nf);
            if g.is_open(nf) && g.files[nf].is_none() { return Err(VfsError::Ebusy); }
            let old = g.files[nf].take();
            g.files[nf] = Some(Arc::clone(&f));
            g.set_open(nf, true);
            g.set_cloexec_bit(nf, false);
            old
        };
        crate::file::fire_clone_hook(&f);
        if let Some(old) = replaced {
            let _ = old.flush();
            drop(old);
            super::fire_file_ref_drop_hook();
        }
        Ok(new_fd)
    }
    pub fn dup3(&self, old_fd: i32, new_fd: i32, flags: OpenFlags) -> KResult<i32> {
        self.dup3_limit(old_fd, new_fd, flags, FD_TABLE_MAX)
    }
    pub fn dup3_limit(&self, old_fd: i32, new_fd: i32, flags: OpenFlags, limit: usize) -> KResult<i32> {
        if flags.bits() & !OpenFlags::O_CLOEXEC.bits() != 0 { return Err(VfsError::Einval); }
        if old_fd == new_fd { return Err(VfsError::Einval); }
        if new_fd < 0 || (new_fd as usize) >= FD_TABLE_MAX { return Err(VfsError::Ebadf); }
        let max = if limit < FD_TABLE_MAX { limit } else { FD_TABLE_MAX };
        if (new_fd as usize) >= max { return Err(VfsError::Ebadf); }
        let f = self.get(old_fd)?;
        let cloexec = flags.contains(OpenFlags::O_CLOEXEC);
        let nf = new_fd as usize;
        let replaced = {
            let mut g = self.inner.lock();
            g.ensure_capacity(nf);
            if g.is_open(nf) && g.files[nf].is_none() { return Err(VfsError::Ebusy); }
            let old = g.files[nf].take();
            g.files[nf] = Some(Arc::clone(&f));
            g.set_open(nf, true);
            g.set_cloexec_bit(nf, cloexec);
            old
        };
        crate::file::fire_clone_hook(&f);
        if let Some(old) = replaced {
            let _ = old.flush();
            drop(old);
            super::fire_file_ref_drop_hook();
        }
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
    pub fn fork_clone_close_range(&self, first: u32, last: u32, cloexec_only: bool) -> Self {
        let g = self.inner.lock();
        let words = sane_fdtable_words(&g.open_fds);
        let nfiles = words * WORD_BITS;
        let mut files: Vec<Option<Arc<File>>> = Vec::with_capacity(nfiles);
        let mut open_fds = g.open_fds[..words].to_vec();
        let mut cloexec = g.cloexec[..words].to_vec();
        for fd in 0..nfiles {
            let in_range = (fd as u64) >= first as u64 && (fd as u64) <= last as u64;
            if in_range && !cloexec_only {
                files.push(None);
                open_fds[word_idx(fd)] &= !bit_mask(fd);
                cloexec[word_idx(fd)] &= !bit_mask(fd);
                continue;
            }
            if let Some(f) = g.files.get(fd).and_then(|s| s.as_ref()) { crate::file::fire_clone_hook(f); }
            files.push(g.files.get(fd).cloned().unwrap_or(None));
            if in_range && cloexec_only { cloexec[word_idx(fd)] |= bit_mask(fd); }
        }
        Self { inner: sync::Spinlock::new(FdTableInner { files, open_fds, cloexec }) }
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
        for f in removed {
            let _ = f.flush();
            drop(f);
            super::fire_file_ref_drop_hook();
        }
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
        for f in removed {
            let _ = f.flush();
            drop(f);
            super::fire_file_ref_drop_hook();
        }
    }
}
