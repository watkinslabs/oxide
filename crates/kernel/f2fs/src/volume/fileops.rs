//! Writing a file's bytes, and shortening one.
//!
//! A small file lives INSIDE its inode. It stays there until a write does not
//! fit, at which point it is converted: the inline bytes become block zero and
//! the flags come off. Writing past the inline region without converting would
//! write the file's own data over its address array.
//!
//! Shortening frees blocks AND the nodes that held them. A direct node left
//! behind with every address cleared is a block nothing can reach and nothing
//! will ever free — the leak the segment table cannot see, because the block
//! still reads as live.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::*;
use crate::limits::MAX_IO_BYTES;
use crate::uapi::*;

use super::dnode::{put32, put64, Holder};
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Write `data` into `ino` at byte offset `off`.
    ///
    /// Returns the BYTES WRITTEN, which may be fewer than asked for. Space and
    /// quota are charged one block at a time, so a write can run out part way
    /// through; the blocks that landed have landed, and reporting the whole
    /// call as failed would tell the caller its file is unchanged when it is
    /// not. The error is reported only when nothing at all was written.
    ///
    /// A write inside the file's existing length does not shorten it, and a
    /// write past the end grows it — the gap in between is a hole, not zeroes
    /// written out.
    /// # C: O(bytes written)
    pub fn write_file(&mut self, ino: u32, off: u64, data: &[u8]) -> Result<usize, Errno> {
        self.writable_or_err()?;
        if data.len() > MAX_IO_BYTES { return Err(Errno::Efbig); }
        if data.is_empty() { return Ok(0); }
        let inode = self.read_inode(ino)?;
        // Writing an encrypted file needs its key: the bytes that reach the
        // medium are ciphertext, and there is no plaintext form of a block on
        // an encrypted volume.
        let crypt = self.crypt_info(&inode, ino)?;
        if inode.encrypted() && crypt.is_none() { return Err(Errno::Enokey); }
        // A verity file is sealed: its contents are what its hash tree attests
        // to, so changing them would leave the attestation describing bytes
        // that are no longer there.
        crate::verity::access::open_write(inode.flags).map_err(crate::verity::access::errno)?;
        // A span holds its writes in a shadow inode until it is committed, and
        // a pinned file is written in place because something outside the
        // filesystem is holding its addresses. Both replace the block loop
        // below rather than feeding it.
        if self.is_atomic_file(ino) { return self.atomic_write_file(ino, off, data); }
        if crate::pin::state::is_pinned(&inode) { return self.pinned_write(ino, off, data); }
        // A compressed file is written a whole CLUSTER at a time, so it cannot
        // go through the block-at-a-time path below at all. The two are not
        // combinable here: a compressed cluster is encrypted as its stored
        // IMAGE, which means the encryption has to happen inside the cluster
        // writer rather than around it, and that writer does not do it yet.
        // Refusing is the only honest answer — writing the image in the clear
        // on an encrypted file would put the file's bytes on the medium.
        if inode.compressed() {
            if inode.encrypted() { return Err(Errno::Eopnotsupp); }
            return self.write_compressed(ino, off, data);
        }
        let end = off.checked_add(data.len() as u64).ok_or(Errno::Efbig)?;
        if inode.inline_data() {
            let (_, len) = inode.inline_data_span();
            if end <= len as u64 {
                self.write_inline(ino, off, data)?;
                return Ok(data.len());
            }
            self.convert_inline(ino)?;
        }
        let mut done = 0usize;
        let mut stopped: Option<Errno> = None;
        while done < data.len() {
            let pos = off + done as u64;
            let index = pos / BLKSIZE as u64;
            let skew = (pos % BLKSIZE as u64) as usize;
            let take = (BLKSIZE - skew).min(data.len() - done);
            if let Err(e) = self.write_one_block(ino, index, skew, &data[done..done + take]) {
                stopped = Some(e);
                break;
            }
            done += take;
        }
        // What landed is recorded even when the rest did not: the size, the
        // block count and the cached extent all describe blocks that now
        // exist, and leaving them behind would make the file disagree with
        // its own contents.
        if done > 0 {
            let size = (off + done as u64).max(self.read_inode(ino)?.size);
            let blocks = self.count_blocks(ino)?;
            self.stamp_inode(ino, |b| {
                put64(b, I_SIZE, size);
                Self::set_iblocks(b, blocks);
            })?;
            self.refresh_extent(ino)?;
        }
        match stopped {
            Some(e) if done == 0 => Err(e),
            _ => Ok(done),
        }
    }

    /// Write into the region inside the inode itself. # C: O(BLKSIZE)
    fn write_inline(&mut self, ino: u32, off: u64, data: &[u8]) -> Result<u64, Errno> {
        let inode = self.read_inode(ino)?;
        let (at, len) = inode.inline_data_span();
        let start = at + off as usize;
        if start + data.len() > at + len { return Err(Errno::Enospc); }
        let size = (off + data.len() as u64).max(inode.size);
        let existed = inode.has(DATA_EXIST);
        let mut block = self.inode_bytes(ino)?;
        // A region that never held data holds the address array's old bytes;
        // they are cleared rather than left to show through a hole.
        if !existed { block[at..at + len].fill(0); }
        block[start..start + data.len()].copy_from_slice(data);
        block[I_INLINE] |= INLINE_DATA | DATA_EXIST;
        put64(&mut block, I_SIZE, size);
        Self::set_iblocks(&mut block, 1);
        self.put_inode(ino, block)?;
        Ok(size)
    }

    /// Move an inline file's bytes out into block zero. # C: O(BLKSIZE)
    pub(crate) fn convert_inline(&mut self, ino: u32) -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        if !inode.inline_data() { return Ok(()); }
        let (at, len) = inode.inline_data_span();
        let block = self.inode_bytes(ino)?;
        let payload: Vec<u8> =
            if inode.has(DATA_EXIST) { block[at..at + len].to_vec() } else { Vec::new() };
        // The flags come off BEFORE the address is recorded: the address array
        // and the inline region are the same bytes, so a reader seeing both
        // would take the data as an address.
        self.stamp_inode(ino, |b| {
            b[I_INLINE] &= !(INLINE_DATA | DATA_EXIST);
            let base = OFFSET_OF_END_OF_I_EXT + le16(b, I_EXTRA_ISIZE).unwrap_or(0) as usize;
            b[base..base + 4].copy_from_slice(&0u32.to_le_bytes());
            // The WHOLE region, not just the first slot: those bytes are the
            // address array, and every byte of file content left in them is
            // read afterwards as a block address. A file of 0x01 bytes leaves
            // 0x01010101 in a slot, which is either an I/O error or — worse —
            // a live address belonging to some other file.
            b[at..at + len].fill(0);
        })?;
        if !payload.is_empty() {
            let is_dir = self.read_inode(ino)?.mode & mode_ifmt() == mode_ifdir();
            // The bytes leave the inode for a block of their own. That block
            // is one the owner did not hold a moment ago — an inline file
            // occupies its inode and nothing else — so it is charged like any
            // other block a file gains, and given back if it cannot be had.
            self.reserve_space(ino, BLKSIZE as u64)?;
            let addr = match self.write_data(ino, 0, is_dir, NULL_ADDR, &payload) {
                Ok(addr) => addr,
                Err(e) => {
                    self.release_reserved_space(ino, BLKSIZE as u64)?;
                    return Err(e);
                }
            };
            self.claim_space(ino, BLKSIZE as u64)?;
            self.set_holder_addr(ino, Holder::Inode, 0, addr)?;
        }
        Ok(())
    }

    /// Read-modify-write one block of a file.
    ///
    /// The owner's quota is PROMISED before the block exists and taken up once
    /// it does. The promise is what the limit refuses, so a write that is
    /// going to be refused is refused before anything is allocated; and an
    /// allocation that fails after the promise gives it straight back, which
    /// is why a write that ends in `ENOSPC` leaves nothing charged to anybody.
    /// # C: O(BLKSIZE)
    pub(crate) fn write_one_block(&mut self, ino: u32, index: u64, skew: usize, data: &[u8])
        -> Result<(), Errno> {
        let (holder, ofs) = self.dnode_for_write(ino, index)?;
        let old = self.holder_addr(ino, holder, ofs)?;
        // A reservation is a hole too: it holds room against the VOLUME's
        // count and was never charged to the owner, so the block that lands
        // on it is this owner's first charge for it.
        let fresh = crate::node::is_hole(old);
        if fresh { self.reserve_space(ino, BLKSIZE as u64)?; }
        let addr = match self.write_page(ino, index, skew, data, (holder, ofs, old)) {
            Ok(addr) => addr,
            Err(e) => {
                if fresh { self.release_reserved_space(ino, BLKSIZE as u64)?; }
                return Err(e);
            }
        };
        // The block exists now, so the promise becomes occupancy.
        if fresh { self.claim_space(ino, BLKSIZE as u64)?; }
        // The room a reservation was holding is the room this block just took.
        if old == NEW_ADDR { self.release_reservation(); }
        self.set_holder_addr(ino, holder, ofs, addr)
    }

    /// Build the page this write leaves behind and put it somewhere.
    ///
    /// Everything between the promise and the block existing lives here, so
    /// the caller has one place to give the promise back from.
    /// # C: O(BLKSIZE)
    fn write_page(&mut self, ino: u32, index: u64, skew: usize, data: &[u8],
                  slot: (Holder, usize, u32)) -> Result<u32, Errno> {
        let (holder, ofs, old) = slot;
        let mut page = if crate::node::is_hole(old) {
            vec![0u8; BLKSIZE]
        } else {
            self.read_main_block(old)?
        };
        let inode = self.read_inode(ino)?;
        // A read-modify-write of an encrypted block happens over PLAINTEXT:
        // the block on the medium is ciphertext, so it is decrypted, patched
        // and encrypted again. Patching the ciphertext in place would corrupt
        // every byte of the unit the write lands in, not just the bytes it
        // meant to change.
        let crypt = self.crypt_info(&inode, ino)?;
        if inode.encrypted() && crypt.is_none() { return Err(Errno::Enokey); }
        if let (Some(c), false) = (&crypt, crate::node::is_hole(old)) {
            let per = (BLKSIZE / c.data_unit_size()) as u64;
            c.crypt_contents(index * per, &mut page, false).map_err(|e| e.errno())?;
        }
        page[skew..skew + data.len()].copy_from_slice(data);
        if let Some(c) = &crypt {
            let per = (BLKSIZE / c.data_unit_size()) as u64;
            c.crypt_contents(index * per, &mut page, true).map_err(|e| e.errno())?;
        }
        let is_dir = inode.mode & mode_ifmt() == mode_ifdir();
        let owner = match holder { Holder::Inode => ino, Holder::Direct(nid) => nid };
        self.write_data(owner, ofs as u16, is_dir, old, &page)
    }

    /// Shorten (or extend) a file to `len`.
    ///
    /// Extending allocates nothing: the new tail is a hole, which is what
    /// makes a sparse file sparse.
    /// # C: O(blocks released)
    pub fn truncate_file(&mut self, ino: u32, len: u64) -> Result<(), Errno> {
        self.writable_or_err()?;
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::Truncate) {
            return Err(Errno::Eio);
        }
        let inode = self.read_inode(ino)?;
        crate::verity::access::truncate(inode.flags).map_err(crate::verity::access::errno)?;
        crate::pin::policy::truncate(crate::pin::state::is_pinned(&inode), inode.size, len,
                                     u64::from(self.blks_per_sec()) * BLKSIZE as u64)?;
        // Blocks come off a compressed file a whole CLUSTER at a time: the
        // cluster the new end falls inside holds one image rather than one
        // block per block, so it is rewritten rather than shortened.
        if inode.compressed() {
            if inode.encrypted() { return Err(Errno::Eopnotsupp); }
            return self.truncate_compressed(ino, len);
        }
        if inode.inline_data() {
            let (at, region) = inode.inline_data_span();
            let keep = (len as usize).min(region);
            let mut block = self.inode_bytes(ino)?;
            block[at + keep..at + region].fill(0);
            put64(&mut block, I_SIZE, len);
            self.put_inode(ino, block)?;
            if len as usize <= region { return Ok(()); }
            // A file grown past its inline region stops being inline.
            self.convert_inline(ino)?;
        }
        let first_gone = len.div_ceil(BLKSIZE as u64);
        self.truncate_tail(ino, first_gone)?;
        // The last kept block's tail is zeroed: it is on the medium whole, and
        // a later write past `len` would otherwise expose the old bytes.
        let skew = (len % BLKSIZE as u64) as usize;
        if skew != 0 && len < inode.size {
            let index = len / BLKSIZE as u64;
            let (holder, ofs) = self.dnode_for_write(ino, index)?;
            let old = self.holder_addr(ino, holder, ofs)?;
            if !crate::node::is_hole(old) {
                let mut page = self.read_main_block(old)?;
                page[skew..].fill(0);
                self.write_one_block(ino, index, 0, &page)?;
            }
        }
        let blocks = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| {
            put64(b, I_SIZE, len);
            Self::set_iblocks(b, blocks);
        })?;
        self.refresh_extent(ino)
    }

}

/// The mode word's type field, and the value that means directory.
/// # C: O(1)
pub const fn mode_ifmt() -> u16 { crate::mode::S_IFMT }
/// # C: O(1)
pub const fn mode_ifdir() -> u16 { crate::mode::S_IFDIR }

/// Write a file's stored depth, used when a directory grows a level.
/// # C: O(1)
pub fn set_depth(block: &mut [u8], depth: u32) { put32(block, I_CURRENT_DEPTH, depth); }

#[cfg(test)]
#[path = "../tests/filewrite.rs"]
mod tests;
