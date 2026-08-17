//! Putting the cipher on one block and taking it off again, given a record the
//! caller already holds.
//!
//! Every function here takes the inode's key as an argument. None of them can
//! fetch one, which is the point: the layer that decides WHICH key is the entry
//! point (`setup`), and the layer that applies it is this one.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::crypto::Info;
use crate::uapi::BLKSIZE;

use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Read one block, letting the medium decrypt it when it holds ciphertext
    /// the block layer is responsible for. # C: O(BLKSIZE)
    pub(crate) fn read_block_crypt(&self, addr: u32, ctx: Option<&block::crypto::Ctx>)
        -> Result<Vec<u8>, Errno> {
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::ReadIo) {
            return Err(Errno::Eio);
        }
        if u64::from(addr) >= self.sb.max_blkaddr() { return Err(Errno::Eio); }
        let mut buf = vec![0u8; BLKSIZE];
        self.source.read_sectors_crypt(u64::from(addr), &mut buf, ctx)?;
        Ok(buf)
    }

    /// Read one main-area block and hand back its PLAINTEXT.
    ///
    /// The one entry point a contents read of an encrypted file takes,
    /// whichever layer does the decryption: the block layer when the inode
    /// uses inline encryption, this filesystem otherwise. Two entry points
    /// would be two places for a caller to forget one of the two.
    /// # C: O(BLKSIZE)
    pub(crate) fn read_main_plain(&self, addr: u32, crypt: Option<&Info>, index: u64)
        -> Result<Vec<u8>, Errno> {
        let ctx = crypt.and_then(|c| c.crypt_ctx(self.first_unit(c, index)));
        if !self.sb_main_contains(addr) { return Err(Errno::Eio); }
        let mut page = self.read_block_crypt(addr, ctx.as_ref())?;
        // A software-encrypted inode is decrypted here; an inline one already
        // came back as plaintext, and running the cipher again would turn it
        // into something no reader can recover.
        if let Some(c) = crypt {
            if !c.uses_inline_crypto() {
                c.crypt_contents(self.first_unit(c, index), &mut page, false)
                    .map_err(|e| e.errno())?;
            }
        }
        Ok(page)
    }

    /// The data unit index one block's worth of contents starts at.
    ///
    /// A data unit may be SMALLER than a block, so this is not the block
    /// index; a policy with a sub-block unit counts several units per block
    /// and the number the first one carries is what the whole block's
    /// encryption starts from.
    /// # C: O(1)
    pub(crate) fn first_unit(&self, crypt: &Info, index: u64) -> u64 {
        index * (BLKSIZE / crypt.data_unit_size()) as u64
    }

    /// The context one block's worth of contents at `index` is written under,
    /// or `None` when this filesystem does the encryption itself. # C: O(1)
    pub(crate) fn write_ctx(&self, crypt: Option<&Info>, index: u64)
        -> Option<block::crypto::Ctx> {
        crypt.and_then(|c| c.crypt_ctx(self.first_unit(c, index)))
    }
}
