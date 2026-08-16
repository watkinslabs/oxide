//! A file's bytes.
//!
//! Two sources, and which one a file uses is a per-inode flag rather than a
//! per-volume one: a small file's data lives INSIDE the inode block, in the
//! space the address array would otherwise occupy. Reading such a file through
//! the address array reads its own bytes as block addresses.
//!
//! A hole reads as zeroes, not as an error and not as whatever the address
//! zero happens to hold.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::DATA_EXIST;
use crate::limits::MAX_IO_BYTES;
use crate::node::Inode;
use crate::uapi::BLKSIZE;

use super::map::Mapped;
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Read from `inode` at byte offset `off` into `buf`.
    ///
    /// Reads stop at the file's size: the last block is whole on the medium
    /// and its tail is padding, so returning it would return bytes the file
    /// does not have.
    /// # C: O(bytes read)
    pub fn read_file(&self, inode: &Inode, ino: u32, off: u64, buf: &mut [u8])
        -> Result<usize, Errno> {
        if off >= inode.size { return Ok(0); }
        let want = buf.len().min((inode.size - off) as usize).min(MAX_IO_BYTES);
        if want == 0 { return Ok(0); }
        if inode.inline_data() { return self.read_inline(inode, ino, off, &mut buf[..want]); }
        let mut done = 0usize;
        while done < want {
            let pos = off + done as u64;
            let index = pos / BLKSIZE as u64;
            let skew = (pos % BLKSIZE as u64) as usize;
            let take = (BLKSIZE - skew).min(want - done);
            match self.map_block(inode, ino, index)? {
                Mapped::Hole => buf[done..done + take].fill(0),
                Mapped::Compressed => return Err(Errno::Eopnotsupp),
                Mapped::At(addr) => {
                    let block = self.read_main_block(addr)?;
                    buf[done..done + take].copy_from_slice(&block[skew..skew + take]);
                }
            }
            done += take;
        }
        Ok(want)
    }

    /// Read a file whose data lives in its own inode block.
    ///
    /// The flag saying the data is inline and the flag saying data EXISTS are
    /// separate: an inline file that has never been written carries the first
    /// and not the second, and its region holds whatever the inode's address
    /// array held.
    /// # C: O(bytes read)
    fn read_inline(&self, inode: &Inode, ino: u32, off: u64, buf: &mut [u8])
        -> Result<usize, Errno> {
        if !inode.has(DATA_EXIST) { buf.fill(0); return Ok(buf.len()); }
        let n = self.read_inode_ref(ino)?.1;
        let (at, len) = inode.inline_data_span();
        let start = at + off as usize;
        let avail = len.saturating_sub(off as usize);
        let take = buf.len().min(avail);
        let src = n.block.get(start..start + take).ok_or(Errno::Eio)?;
        buf[..take].copy_from_slice(src);
        buf[take..].fill(0);
        Ok(buf.len())
    }

    /// The whole of a file. # C: O(file bytes)
    pub fn read_whole(&self, inode: &Inode, ino: u32) -> Result<Vec<u8>, Errno> {
        let len = usize::try_from(inode.size).map_err(|_| Errno::Efbig)?;
        if len > MAX_IO_BYTES { return Err(Errno::Efbig); }
        let mut out = vec![0u8; len];
        let got = self.read_file(inode, ino, 0, &mut out)?;
        out.truncate(got);
        Ok(out)
    }

    /// The target of a symbolic link.
    ///
    /// A link's target is its file content, so a short one is inline and a
    /// long one is not — the same two paths as any other file, which is why
    /// this is the file reader rather than a second one.
    /// # C: O(target bytes)
    pub fn read_link(&self, inode: &Inode, ino: u32) -> Result<Vec<u8>, Errno> {
        let mut bytes = self.read_whole(inode, ino)?;
        // A stored target may carry its terminator; a path with a trailing
        // zero byte in it resolves to nothing.
        if let Some(pos) = bytes.iter().position(|&b| b == 0) { bytes.truncate(pos); }
        if bytes.is_empty() { return Err(Errno::Eio); }
        Ok(bytes)
    }
}
