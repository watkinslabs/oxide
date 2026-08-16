//! Pinning and unpinning a file, and what a pinned file's writes do.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::F2FS_COMPR_FL;
use crate::mode;
use crate::node::Inode;
use crate::opts::Mode;
use crate::uapi::*;
use crate::volume::curseg::Summary;
use crate::volume::dnode::put32;
use crate::volume::map::Mapped;
use crate::volume::Volume;

use super::policy::{self, PinAction, PinFacts, SetPinGate};
use super::state;

impl<S: SectorSource> Volume<S> {
    /// Whether `ino` carries the pin mark. # C: O(1 block)
    pub fn is_pinned_ino(&self, ino: u32) -> Result<bool, Errno> {
        Ok(state::is_pinned(&self.read_inode(ino)?))
    }

    /// What `GET_PIN_FILE` reports: the recorded collisions for a pinned file,
    /// and zero for one that is not pinned at all.
    ///
    /// The two are told apart by the count only when the file has collided,
    /// which is the reference's own shape — the interface reports a risk
    /// signal, not a boolean.
    /// # C: O(1 block)
    pub fn get_pin_file(&self, ino: u32) -> Result<u32, Errno> {
        let inode = self.read_inode(ino)?;
        if !state::is_pinned(&inode) { return Ok(0); }
        Ok(u32::from(self.gc_failures_of(ino, &inode)?))
    }

    /// Set or clear the pin mark, and report the collision count.
    /// # C: O(1 block), plus the inline conversion when there is one
    pub fn set_pin_file(&mut self, ino: u32, pin: u32) -> Result<u32, Errno> {
        let inode = self.read_inode(ino)?;
        let gate = SetPinGate {
            is_reg: mode::file_type(inode.mode) == vfs::FileType::Regular,
            ro_mount: !self.writable,
            device_alias: crate::flags::FEATURE_DEVICE_ALIAS & self.sb.feature != 0,
        };
        let facts = self.pin_facts(ino, &inode)?;
        match policy::set_pin_file(&gate, &facts, pin)? {
            PinAction::Unpin => {
                let m = inode.mode;
                self.stamp_inode(ino, |b| {
                    state::set_pin(b, false);
                    state::set_gc_failures(b, m, 0);
                })?;
                Ok(0)
            }
            PinAction::AlreadyPinned => Ok(u32::from(facts.gc_failures)),
            PinAction::Pin => {
                self.convert_inline(ino)?;
                let now = self.read_inode(ino)?;
                policy::pin_compression(now.compressed() && now.blocks > 1)?;
                self.stamp_inode(ino, |b| {
                    // A compressed file with no compressed blocks stops being
                    // compressed rather than being refused: nothing has been
                    // stored the cluster reader would have to unpack.
                    let flags = le32(b, I_FLAGS).unwrap_or(0) & !F2FS_COMPR_FL;
                    put32(b, I_FLAGS, flags);
                    state::set_pin(b, true);
                })?;
                Ok(u32::from(self.gc_failures_of(ino, &now)?))
            }
        }
    }

    /// Put the mark on or take it off with no ladder at all.
    ///
    /// Swap activation pins the file it is given after it has checked what it
    /// needs to check, which is a different set of conditions from the ones a
    /// caller asking to pin has to satisfy.
    /// # C: O(1 block)
    pub(crate) fn mark_pinned(&mut self, ino: u32, on: bool) -> Result<(), Errno> {
        let m = self.read_inode(ino)?.mode;
        self.stamp_inode(ino, |b| {
            state::set_pin(b, on);
            if !on { state::set_gc_failures(b, m, 0); }
        })
    }

    /// Collisions recorded against `ino`. # C: O(1 block)
    pub(crate) fn gc_failures_of(&self, ino: u32, inode: &Inode) -> Result<u16, Errno> {
        let n = self.read_inode_ref(ino)?.1;
        Ok(state::gc_failures(&n.block, inode.mode))
    }

    /// Everything the pin decision reads. # C: O(1 block)
    pub(crate) fn pin_facts(&self, ino: u32, inode: &Inode) -> Result<PinFacts, Errno> {
        Ok(PinFacts {
            atomic: self.is_atomic_file(ino),
            already_pinned: state::is_pinned(inode),
            has_blocks: inode.blocks > 1,
            blkzoned: self.sb.feature & crate::flags::FEATURE_BLKZONED != 0,
            update_outplace: self.should_update_outplace(ino, inode),
            gc_failures: self.gc_failures_of(ino, inode)?,
            threshold: policy::GC_PIN_FILE_THRESHOLD,
        })
    }

    /// Whether something about this file forces every write out of place.
    ///
    /// A pinned file's whole promise is that its blocks stay where they are,
    /// so a file that must be rewritten elsewhere on every change cannot be
    /// pinned — the two rules would contradict each other on the first write.
    /// # C: O(1)
    pub(crate) fn should_update_outplace(&self, ino: u32, inode: &Inode) -> bool {
        if state::is_pinned(inode) { return false; }
        if self.opts.mode == Mode::Lfs { return true; }
        if mode::file_type(inode.mode) == vfs::FileType::Directory { return true; }
        // A quota file's blocks are rewritten under the allocation they are
        // accounting for, so overwriting one in place would record the change
        // inside the transaction that caused it.
        if self.is_quota_file(ino) { return true; }
        if self.is_atomic_file(ino) || self.is_cow_file(ino) { return true; }
        false
    }

    /// Record a collision against a pinned file, and give up on the pin once
    /// the file has cost too many.
    /// # C: O(1 block)
    pub fn pin_file_control(&mut self, ino: u32, inc: bool) -> Result<u16, Errno> {
        let inode = self.read_inode(ino)?;
        let now = self.gc_failures_of(ino, &inode)?;
        match policy::pin_file_control(now, policy::GC_PIN_FILE_THRESHOLD, inc) {
            Err(e) => {
                self.stamp_inode(ino, |b| state::set_pin(b, false))?;
                Err(e)
            }
            Ok(next) => {
                if next != now {
                    let m = inode.mode;
                    self.stamp_inode(ino, |b| state::set_gc_failures(b, m, next))?;
                }
                Ok(next)
            }
        }
    }

    /// The owning inode of the data block a summary entry names, when that
    /// inode is pinned.
    ///
    /// The cleaner asks this of every data block it is about to move: a
    /// pinned block stays where it is, and the collision is recorded against
    /// the file that caused it.
    /// # C: O(2 blocks)
    pub fn pinned_owner_ino(&self, s: &Summary) -> Result<Option<u32>, Errno> {
        let Ok(n) = self.read_node(s.nid, None) else { return Ok(None) };
        let ino = n.footer.ino;
        match self.read_inode(ino) {
            Ok(i) if state::is_pinned(&i) => Ok(Some(ino)),
            _ => Ok(None),
        }
    }

    /// Whether every block the range touches already exists.
    /// # C: O(blocks in range) node reads
    pub(crate) fn pinned_overwrite(&self, ino: u32, off: u64, count: usize)
        -> Result<bool, Errno> {
        if count == 0 { return Ok(true); }
        let inode = self.read_inode(ino)?;
        let first = off / BLKSIZE as u64;
        let last = (off + count as u64 - 1) / BLKSIZE as u64;
        for index in first..=last {
            if !matches!(self.map_block(&inode, ino, index)?, Mapped::At(_)) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Write into a pinned file.
    ///
    /// Only an overwrite is allowed, and it happens in place. A write that
    /// would have to allocate is refused with `EIO` rather than served from
    /// wherever the allocator happened to be: the caller holding this file's
    /// addresses was promised they do not change, and quietly giving it a
    /// block somewhere else keeps the promise's words and breaks its meaning.
    /// # C: O(bytes written)
    pub fn pinned_write(&mut self, ino: u32, off: u64, data: &[u8]) -> Result<usize, Errno> {
        self.writable_or_err()?;
        if data.is_empty() { return Ok(0); }
        policy::write_allowed(true, self.pinned_overwrite(ino, off, data.len())?)?;
        let mut done = 0usize;
        while done < data.len() {
            let pos = off + done as u64;
            let index = pos / BLKSIZE as u64;
            let skew = (pos % BLKSIZE as u64) as usize;
            let take = (BLKSIZE - skew).min(data.len() - done);
            self.pinned_write_block(ino, index, skew, &data[done..done + take])?;
            done += take;
        }
        Ok(done)
    }

    /// Rewrite one block of a pinned file WHERE IT LIES.
    ///
    /// The out-of-place write every other file gets would move the block,
    /// which is the one thing pinning promised would not happen. The address
    /// is therefore unchanged, no log advances, and the segment table is not
    /// touched: nothing about the block's liveness changed, only its bytes.
    /// # C: O(BLKSIZE)
    pub(crate) fn pinned_write_block(&mut self, ino: u32, index: u64, skew: usize, data: &[u8])
        -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        let Mapped::At(addr) = self.map_block(&inode, ino, index)? else {
            // Refused before this by the write gate; reaching it means the
            // gate and the map disagree, which is not a write to guess at.
            return Err(Errno::Eio);
        };
        let crypt = self.crypt_info(&inode, ino)?;
        if inode.encrypted() && crypt.is_none() { return Err(Errno::Enokey); }
        let mut page = self.read_main_block(addr)?;
        if let Some(c) = &crypt {
            let per = (BLKSIZE / c.data_unit_size()) as u64;
            c.crypt_contents(index * per, &mut page, false).map_err(|e| e.errno())?;
        }
        page[skew..skew + data.len()].copy_from_slice(data);
        if let Some(c) = &crypt {
            let per = (BLKSIZE / c.data_unit_size()) as u64;
            c.crypt_contents(index * per, &mut page, true).map_err(|e| e.errno())?;
        }
        self.write_block(addr, &page)?;
        self.dirty = true;
        Ok(())
    }
}
