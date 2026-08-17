//! The two inodes, start to finish.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::Inode;
use crate::uapi::I_SIZE;
use crate::volume::dnode::put64;
use crate::volume::Volume;

use super::plan::{self, Facts};

impl<S: SectorSource> Volume<S> {
    /// Move `len` bytes of `src` at `pos_in` into `dst` at `pos_out`.
    ///
    /// Both inodes are named by number rather than by descriptor because the
    /// descriptor pair is the layer above's problem: which mount each is on,
    /// and whether both were opened for the access this needs, are facts about
    /// the open descriptions and cannot be recovered from a volume.
    /// # C: O(blocks moved) blocks
    pub fn move_file_range(&mut self, src: u32, pos_in: u64, dst: u32, pos_out: u64, len: u64)
        -> Result<(), Errno> {
        let same = src == dst;
        // Blocks change owner between the two files, so both identities are
        // acquired before either side is touched.
        self.dquot_initialize_pair(src, dst)?;
        // Both files' pending writes go down first: this rearranges the
        // addresses on either side, and a page not yet placed has none.
        self.flush_data_pages(src)?;
        if src != dst { self.flush_data_pages(dst)?; }
        let src_inode = self.read_inode(src)?;
        let dst_inode = if same { src_inode.clone() } else { self.read_inode(dst)? };
        let sf = self.facts_of(&src_inode, src);
        let df = self.facts_of(&dst_inode, dst);
        let Some(p) = plan::plan(same, self.writable(), &sf, &df, pos_in, pos_out, len)? else {
            return Ok(());
        };

        // Both files' bytes have to be in BLOCKS before their addresses can
        // change owner: an inline file's bytes live inside its inode, where
        // there is no address to hand over and none to receive one.
        self.convert_inline(src)?;
        if !same { self.convert_inline(dst)?; }

        self.exchange_blocks(src, dst, p.src_index, p.dst_index, p.blocks)?;

        // The counts are recomputed from the trees rather than adjusted by
        // what was moved: a hole in the source moved nothing, and an adjusted
        // count would drift by one per hole with nothing reporting it.
        let src_blocks = self.count_blocks(src)?;
        self.stamp_inode(src, |b| Volume::<S>::set_iblocks(b, src_blocks))?;
        let dst_blocks = self.count_blocks(dst)?;
        self.stamp_inode(dst, |b| {
            put64(b, I_SIZE, p.dst_size);
            Volume::<S>::set_iblocks(b, dst_blocks);
        })?;
        self.refresh_extent(src)?;
        if !same { self.refresh_extent(dst)?; }

        let now = (self.clock, 0);
        self.touch(src, now)?;
        if !same { self.touch(dst, now)?; }
        Ok(())
    }

    /// One inode as the ladder reads it, with the mount state the stored
    /// inode cannot carry folded in. # C: O(1)
    fn facts_of(&self, i: &Inode, ino: u32) -> Facts {
        Facts {
            is_reg: crate::mode::file_type(i.mode) == vfs::FileType::Regular,
            size: i.size,
            encrypted: i.encrypted(),
            compressed: i.compressed(),
            pinned: crate::pin::state::is_pinned(i),
            atomic: self.is_atomic_file(ino),
        }
    }
}

#[cfg(test)]
#[path = "../tests/moverange/run.rs"]
mod tests;
