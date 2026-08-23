//! One block, off the medium or out of the mount's metadata mapping.
//!
//! Every read this filesystem makes of a block it addresses itself passes
//! through `read_block`. That is what makes the metadata mapping possible at
//! all: one place answers, so one place can answer without asking the device.
//! A second reader beside it would be a second answer to "what is at this
//! address", and the one that skipped the mapping would return the bytes the
//! block held before the last write.
//!
//! The exception is deliberate and is not metadata: a file whose contents the
//! block layer deciphers is read through `crypto`, which hands the medium a
//! key context this path has no business carrying. Those addresses are all in
//! the main area, which the mapping does not cover.
//!
//! The write half is here for the same reason: one place decides that an
//! address outside the main area is metadata, keeps the mapping in step with
//! what landed, and notes which member the write went to. A second writer beside
//! it would be a second answer to all three.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::BLKSIZE;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Read one block by its address.
    ///
    /// Addresses are in blocks and the source is addressed in blocks, so the
    /// two units are the same here by construction — which is why the source
    /// is created at the volume's block size rather than at a sector size.
    /// # C: O(1) held, O(BLKSIZE) otherwise
    pub fn read_block(&self, addr: u32) -> Result<Vec<u8>, Errno> {
        if u64::from(addr) >= self.sb.max_blkaddr() { return Err(Errno::Eio); }
        // Ahead of the injected failure, because the failure is the DEVICE's:
        // a block served from the mapping submits no request, so there is
        // nothing for a read-fault site to fail. A mount that injected here
        // would report an I/O error for an I/O that never happened.
        let meta = self.meta_cache.covers(addr);
        if meta {
            if let Some(held) = self.meta_cache.load(addr) { return Ok(held); }
        }
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::ReadIo) {
            return Err(Errno::Eio);
        }
        let mut buf = vec![0u8; BLKSIZE];
        self.source.read_sectors(u64::from(addr), &mut buf)?;
        // Everything OUTSIDE the main area is metadata by the layout's own
        // definition, which is the same derivation the write path uses to
        // decide a block is metadata. The main-area reads — nodes, file data,
        // the cleaner's copies — are charged by the typed readers above this
        // one, because the address cannot tell those three apart.
        //
        // Charged on the MISS only: a block the mapping answered moved no
        // bytes at the device, and counting it would report traffic the
        // mapping exists to avoid.
        if !self.sb.valid_main_blkaddr(addr) {
            self.io_account(crate::stats::iostat::Io::FsMetaRead, BLKSIZE as u64, false);
        }
        // Offered AFTER the read rather than instead of it: the mapping is
        // filled by what the medium actually returned, so a block that could
        // not be read leaves nothing behind to be served later.
        if meta { self.meta_cache.store(addr, &buf); }
        Ok(buf)
    }

    /// Read one block that must lie in the MAIN area.
    ///
    /// Everything a file or a node points at lives there. An address outside
    /// it names metadata, and following one would read a checkpoint or a table
    /// block as if it were data.
    /// # C: O(BLKSIZE)
    pub fn read_main_block(&self, addr: u32) -> Result<Vec<u8>, Errno> {
        if !self.sb_main_contains(addr) {
            // A node or a file's address array named a block outside the area
            // that can hold one, so the structure that named it is damaged and
            // the volume must reach fsck saying so.
            self.note_error(crate::errrec::Error::InvalidBlkaddr);
            return Err(Errno::Eio);
        }
        self.read_block(addr)
    }

    /// Read a recovery-chain node through the temporary main-area view. # C: O(1 block)
    pub(crate) fn read_por_block(&self, addr: u32) -> Result<Vec<u8>, Errno> {
        if !self.sb_main_contains(addr) { return Err(Errno::Eio); }
        if let Some(held) = self.meta_cache.load_por(addr) { return Ok(held); }
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::ReadIo) {
            return Err(Errno::Eio);
        }
        let mut buf = vec![0u8; BLKSIZE];
        self.source.read_sectors(u64::from(addr), &mut buf)?;
        self.meta_cache.store_por(addr, &buf);
        self.io_account(crate::stats::iostat::Io::FsMetaRead, BLKSIZE as u64, false);
        Ok(buf)
    }

    /// Put `data` at `addr`. # C: O(BLKSIZE)
    pub(crate) fn write_block(&self, addr: u32, data: &[u8]) -> Result<(), Errno> {
        self.write_block_flags(addr, data, block::RequestFlags::NONE)
    }

    /// The same, telling the medium what kind of block this is and how urgent.
    ///
    /// One implementation with the flags defaulted rather than two write
    /// paths: a second entry point is a second place for the fault site, the
    /// length check and the address check to be got wrong.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_block_flags(&self, addr: u32, data: &[u8], flags: block::RequestFlags)
        -> Result<(), Errno> {
        self.write_block_crypt(addr, data, flags, None)
    }

    /// The same, handing the medium the encryption context this block's
    /// contents belong under.
    ///
    /// `None` means the bytes are already what should land — either the file
    /// is not encrypted, or this filesystem enciphered them itself. `Some`
    /// means they are PLAINTEXT and the layer beneath must encrypt them; a
    /// medium that ignored it would put the file's own bytes on the disk.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_block_crypt(&self, addr: u32, data: &[u8],
        flags: block::RequestFlags, ctx: Option<&block::crypto::Ctx>) -> Result<(), Errno> {
        self.write_block_inner(addr, data, flags, ctx, block::Durability::NONE)
    }

    /// The same, under a promise about WHEN the block is on the medium.
    ///
    /// What a checkpoint's commit block is written through, and the only kind of
    /// write that carries one: everything else this filesystem writes is made
    /// durable by the commit block that comes to refer to it. Carries no
    /// encryption context for the reason the medium's own contract gives — a
    /// block written under a promise is this filesystem's metadata, which the
    /// layer below never enciphers.
    /// # C: O(BLKSIZE) plus up to two barriers
    pub(crate) fn write_block_durable(&self, addr: u32, data: &[u8], want: block::Durability)
        -> Result<(), Errno> {
        self.write_block_inner(addr, data, block::RequestFlags::NONE, None, want)
    }

    /// The one write path.
    ///
    /// Everything above defaults into this, rather than each entry point doing
    /// its own: the fault site, the length check, the address check, the
    /// metadata derivation, the accounting, the mapping upkeep and the member
    /// record are each decided ONCE here, and a second copy of any of them is a
    /// second answer that can drift.
    /// # C: O(BLKSIZE)
    fn write_block_inner(&self, addr: u32, data: &[u8], flags: block::RequestFlags,
        ctx: Option<&block::crypto::Ctx>, want: block::Durability) -> Result<(), Errno> {
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::WriteIo) {
            return Err(Errno::Eio);
        }
        if data.len() != BLKSIZE { return Err(Errno::Einval); }
        let main = self.sb.valid_main_blkaddr(addr);
        if !main && u64::from(addr) >= self.sb.max_blkaddr() { return Err(Errno::Eio); }
        // Everything OUTSIDE the main area is metadata by the layout's own
        // definition — the checkpoint packs, both tables, the summary area and
        // the orphan list are the only things there — so the address answers
        // the question and no caller has to remember to. Derived here rather
        // than passed in from each writer because a metadata writer added
        // later would otherwise have to know to say so, and the one that
        // forgot would be indistinguishable from file data.
        let flags = if main { flags } else { flags | block::flags::META };
        if want.is_empty() {
            self.source.write_sectors_crypt(u64::from(addr), data, ctx, flags)?;
        } else {
            self.source.write_sectors_durable(u64::from(addr), data, flags, want)?;
        }
        // Charged by the same derivation that set the flag. A main-area write
        // is a node or a page of data and is charged by the typed writer that
        // knows which; only the metadata areas can be classified from the
        // address alone.
        if !main {
            use crate::stats::iostat::Io;
            let kind = if self.segstate.cp_writing { Io::FsCpMeta } else { Io::FsMeta };
            self.io_account(kind, BLKSIZE as u64, false);
        }
        // Which MEMBER this landed on, so the next checkpoint knows whose cache
        // holds something it depends on. Recorded here for the same reason the
        // metadata derivation is: this is the single point every block write of
        // this filesystem goes through, and a member that became dirty without
        // the checkpoint learning of it would be committed over.
        self.note_device_write(addr);
        // The mapping of metadata blocks is kept in step HERE, after the write
        // landed and nowhere else, because this is the single point every
        // metadata write in this filesystem goes through. A block rewritten
        // without this would still be answered from the mapping with the bytes
        // it held before — a stale read with no error anywhere, which is the
        // one failure a read cache can produce.
        if self.meta_cache.covers(addr) {
            // A context means the LAYER BELOW transforms these bytes before
            // they land, so what is now at the address is not what was passed
            // down and cannot be filed as if it were. No metadata write
            // carries one today; the mapping drops the block rather than
            // depend on that staying true.
            match ctx {
                None => self.meta_cache.overwrite(addr, data),
                Some(_) => self.meta_cache.invalidate_range(addr, 1),
            }
        }
        if self.meta_cache.covers_por(addr) { self.meta_cache.invalidate_range(addr, 1); }
        Ok(())
    }

    /// Metadata blocks this mount is holding. # C: O(1)
    pub fn meta_cached_blocks(&self) -> usize { self.meta_cache.blocks() }

    /// File data pages this mount is holding. # C: O(inodes held)
    pub fn data_cached_pages(&self) -> usize { self.data_cache.pages() }

    /// Reads the file mapping answered without the medium. # C: O(1)
    pub fn data_cache_hits(&self) -> u64 { self.data_cache.hits() }
}
