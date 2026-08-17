//! Stamping a new inode's compression settings.
//!
//! Three fields and one flag bit, written into the inode block before it goes
//! down for the first time. Doing it here rather than after the write is not
//! tidiness: the inode is the thing that records what its own clusters mean,
//! so a file whose settings arrive in a second write is a file that exists,
//! briefly, describing itself wrongly — and a crash in between leaves it that
//! way for good.

use sectors::SectorSource;

use crate::compress::newfile::{decide, NewFile};
use crate::compress::policy::context;
use crate::flags::{F2FS_COMPR_FL, F2FS_NOCOMP_FL};
use crate::uapi::{le16, le32, I_COMPRESS_ALGORITHM, I_COMPRESS_FLAG, I_EXTRA_ISIZE, I_FLAGS,
                  I_LOG_CLUSTER_SIZE, OFFSET_OF_END_OF_I_EXT};

use super::dnode::{put16, put32};
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Apply the mount's compression policy to a new inode block.
    ///
    /// Reports whether the inode came out compressed, which the caller needs:
    /// a compressed file may not also keep its bytes inside the inode, because
    /// the inline region is read as plain bytes and a compressed file's are
    /// not. The two decisions are therefore ordered — compression first, the
    /// inline offer only over what is left — and the ordering is only
    /// expressible if this one answers.
    /// # C: O(list entries * name length)
    pub(crate) fn stamp_new_compress(&self, block: &mut [u8], parent_flags: u32, is_dir: bool,
                                     name: Option<&[u8]>) -> bool {
        if !crate::features::has_compression(self.sb.feature) { return false; }
        let c = &self.opts.compress;
        let hot = self.hot_extensions();
        match decide(is_dir, name, &hot, parent_flags, &c.extensions, &c.noextensions) {
            NewFile::Plain => false,
            NewFile::Refuse => { or_flags(block, F2FS_NOCOMP_FL); false }
            NewFile::Compress => self.set_compress_context(block),
        }
    }

    /// The volume's HOT extensions: the tail of its one list.
    ///
    /// One list holds both temperatures, cold entries first, and only the
    /// count of the cold ones says where the split is. Reading the whole list
    /// as hot would leave every named file uncompressed, which is the opposite
    /// of what the cold half is for.
    /// # C: O(entries)
    fn hot_extensions(&self) -> alloc::vec::Vec<&[u8]> {
        let cold = self.sb.extension_count as usize;
        self.sb
            .extensions
            .iter()
            .skip(cold)
            .take(self.sb.hot_ext_count as usize)
            .map(|e| e.as_bytes())
            .collect()
    }

    /// Write the codec, the cluster width and the flag word onto the inode.
    ///
    /// The three live in the extra region, whose width the volume declares per
    /// inode. A volume too narrow to hold them can record no compressed file
    /// at all: marking one compressed with nothing behind the mark leaves a
    /// stored cluster width of zero, which is not a width the format admits,
    /// so every read of the file would fail on metadata the mount itself
    /// wrote. Such a volume creates the file PLAIN, which is the same outcome
    /// a reader that cannot find the settings arrives at.
    /// # C: O(1)
    fn set_compress_context(&self, b: &mut [u8]) -> bool {
        let extra = le16(b, I_EXTRA_ISIZE).unwrap_or(0) as usize;
        if I_COMPRESS_FLAG + 2 > OFFSET_OF_END_OF_I_EXT + extra { return false; }
        let c = &self.opts.compress;
        let Some((algo, log, flag)) = context(c.algorithm, c.log_size, c.chksum, c.level)
        else { return false };
        b[I_COMPRESS_ALGORITHM] = algo;
        b[I_LOG_CLUSTER_SIZE] = log;
        put16(b, I_COMPRESS_FLAG, flag);
        or_flags(b, F2FS_COMPR_FL);
        true
    }
}

/// Add bits to the inode's stored flag word. # C: O(1)
fn or_flags(b: &mut [u8], bits: u32) {
    let cur = le32(b, I_FLAGS).unwrap_or(0);
    put32(b, I_FLAGS, cur | bits);
}
