//! Reads and writes while a span is open.
//!
//! Writes land in the COW inode's index; reads consult it first and fall back
//! to the file. The bytes are produced as the FILE's throughout — its key, its
//! block index, its verity state — because that is what they will be once the
//! commit moves them across.

use alloc::vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::dnode::{put64, Holder};
use crate::volume::map::Mapped;
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Write into an open span.
    ///
    /// The file's size moves as the writer writes, because the writer is
    /// entitled to read back what it wrote and a read is clamped to the size.
    /// The file's BLOCK COUNT does not: not one of these blocks is the file's
    /// yet.
    /// # C: O(bytes written)
    pub fn atomic_write_file(&mut self, ino: u32, off: u64, data: &[u8])
        -> Result<usize, Errno> {
        let cow = self.atomic_cow_ino(ino).ok_or(Errno::Einval)?;
        let mut done = 0usize;
        let mut stopped: Option<Errno> = None;
        while done < data.len() {
            let pos = off + done as u64;
            let index = pos / BLKSIZE as u64;
            let skew = (pos % BLKSIZE as u64) as usize;
            let take = (BLKSIZE - skew).min(data.len() - done);
            if let Err(e) = self.atomic_write_block(ino, cow, index, skew, &data[done..done + take])
            {
                stopped = Some(e);
                break;
            }
            done += take;
        }
        if done > 0 {
            let size = (off + done as u64).max(self.read_inode(ino)?.size);
            self.stamp_inode(ino, |b| put64(b, I_SIZE, size))?;
            let cow_blocks = self.count_blocks(cow)?;
            self.stamp_inode(cow, |b| Self::set_iblocks(b, cow_blocks))?;
            if let Some(a) = self.atomic.get_mut(&ino) {
                a.dirtied = true;
                a.write_cnt += 1;
            }
        }
        match stopped {
            Some(e) if done == 0 => Err(e),
            _ => Ok(done),
        }
    }

    /// Put one block of the span into the COW inode's index.
    ///
    /// The base the patch is applied to is the COW inode's block when the span
    /// has already written this index, and the FILE's otherwise: a partial
    /// write over bytes the file already holds must keep the bytes it did not
    /// write, and the file is the only place they are.
    /// # C: O(BLKSIZE)
    fn atomic_write_block(&mut self, ino: u32, cow: u32, index: u64, skew: usize, data: &[u8])
        -> Result<(), Errno> {
        let (holder, ofs) = self.dnode_for_write(cow, index)?;
        let old = self.holder_addr(cow, holder, ofs)?;
        if crate::node::is_hole(old) { self.charge_space(cow, BLKSIZE as u64)?; }
        let inode = self.read_inode(ino)?;
        let crypt = self.crypt_info(&inode, ino)?;
        if inode.encrypted() && crypt.is_none() { return Err(Errno::Enokey); }
        // A replacing span shows an empty file, so a base taken from the file
        // would resurrect bytes the span has already made invisible.
        let replace = self.atomic_is_replace(ino);
        let (mut page, ciphered) = if !crate::node::is_hole(old) {
            (self.read_main_block(old)?, true)
        } else if replace {
            (vec![0u8; BLKSIZE], false)
        } else {
            match self.map_block(&inode, ino, index)? {
                Mapped::At(a) => (self.read_main_block(a)?, true),
                _ => (vec![0u8; BLKSIZE], false),
            }
        };
        if let (Some(c), true) = (&crypt, ciphered) {
            let per = (BLKSIZE / c.data_unit_size()) as u64;
            c.crypt_contents(index * per, &mut page, false).map_err(|e| e.errno())?;
        }
        page[skew..skew + data.len()].copy_from_slice(data);
        if let Some(c) = &crypt {
            let per = (BLKSIZE / c.data_unit_size()) as u64;
            c.crypt_contents(index * per, &mut page, true).map_err(|e| e.errno())?;
        }
        let owner = match holder { Holder::Inode => cow, Holder::Direct(nid) => nid };
        let addr = self.write_data(owner, ofs as u16, false, old, &page)?;
        self.set_holder_addr(cow, holder, ofs, addr)
    }

    /// Read from a file with a span open.
    ///
    /// An index the span has written comes out of the COW inode; anything else
    /// comes out of the file, unless the span replaces the file's contents, in
    /// which case anything the span did not write is already a hole as far as
    /// this reader is concerned.
    /// # C: O(bytes read)
    pub fn atomic_read_file(&self, inode: &crate::node::Inode, ino: u32, off: u64,
                                   buf: &mut [u8]) -> Result<usize, Errno> {
        let cow = self.atomic_cow_ino(ino).ok_or(Errno::Einval)?;
        if off >= inode.size { return Ok(0); }
        let want = buf.len().min((inode.size - off) as usize).min(crate::limits::MAX_IO_BYTES);
        if want == 0 { return Ok(0); }
        let cow_inode = self.read_inode(cow)?;
        let crypt = self.crypt_info(inode, ino)?;
        if inode.encrypted() && crypt.is_none() { return Err(Errno::Enokey); }
        let replace = self.atomic_is_replace(ino);
        let mut done = 0usize;
        while done < want {
            let pos = off + done as u64;
            let index = pos / BLKSIZE as u64;
            let skew = (pos % BLKSIZE as u64) as usize;
            let take = (BLKSIZE - skew).min(want - done);
            match self.map_block(&cow_inode, cow, index)? {
                Mapped::At(addr) => {
                    let mut page = self.read_main_block(addr)?;
                    if let Some(c) = &crypt {
                        let per = (BLKSIZE / c.data_unit_size()) as u64;
                        c.crypt_contents(index * per, &mut page, false).map_err(|e| e.errno())?;
                    }
                    buf[done..done + take].copy_from_slice(&page[skew..skew + take]);
                }
                _ if replace => buf[done..done + take].fill(0),
                // The file's own block, read here rather than through the
                // file reader: that reader routes every read of a file with
                // a span open back into this one.
                _ => match self.map_block(inode, ino, index)? {
                    Mapped::At(addr) => {
                        let mut page = self.read_main_block(addr)?;
                        if let Some(c) = &crypt {
                            let per = (BLKSIZE / c.data_unit_size()) as u64;
                            c.crypt_contents(index * per, &mut page, false)
                                .map_err(|e| e.errno())?;
                        }
                        if inode.verity() && !self.verity_check(inode, ino, index, &page)? {
                            return Err(Errno::Eio);
                        }
                        buf[done..done + take].copy_from_slice(&page[skew..skew + take]);
                    }
                    _ => buf[done..done + take].fill(0),
                },
            }
            done += take;
        }
        Ok(want)
    }
}
