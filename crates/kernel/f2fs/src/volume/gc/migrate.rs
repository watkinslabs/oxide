//! Moving one live block out of the victim and repointing its owner.
//!
//! A migration is an ordinary out-of-place write. Nothing about the block
//! changes — same bytes, same owner, same slot — only where it lives, which is
//! the whole point: the victim's remaining live blocks leave, and the segment
//! becomes reclaimable.
//!
//! The owner update is not optional and not deferrable. A block copied without
//! it leaves the file pointing at the old address, which the cleaner is about
//! to hand back to the allocator; the next write into that segment overwrites
//! the file's data with something unrelated.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::footer::Footer;
use crate::uapi::*;

use super::live;
use crate::volume::curseg::{Kind, Summary};
use crate::volume::dnode::Holder;
use crate::volume::Volume;

/// Where a data block's address is recorded: the node, and which file it
/// belongs to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Owner {
    pub holder: Holder,
    pub ino: u32,
}

/// Which holder a node block's footer makes it. # C: O(1)
pub fn owner_of(f: &Footer) -> Owner {
    if f.is_inode() { Owner { holder: Holder::Inode, ino: f.ino } }
    else { Owner { holder: Holder::Direct(f.nid), ino: f.ino } }
}

impl<S: SectorSource> Volume<S> {
    /// The address the owner named by `s` currently records, or `None` when
    /// the owner cannot be read — an owner that no longer exists cannot still
    /// be pointing at the block.
    /// # C: O(1 block)
    pub(crate) fn owner_addr(&self, s: &Summary) -> Option<u32> {
        let n = self.read_node(s.nid, None).ok()?;
        let o = owner_of(&n.footer);
        self.holder_addr(o.ino, o.holder, s.ofs_in_node as usize).ok()
    }

    /// Copy the data block at `addr` into a log and repoint its owner.
    ///
    /// Liveness was settled by the caller and is not re-decided here: two
    /// places deciding whether a block is alive is two answers that can
    /// disagree, and the one that runs second would silently cover for a wrong
    /// first.
    ///
    /// The old block is NOT released here. It is released once the whole
    /// segment has been walked, so the victim keeps live blocks — and stays
    /// ineligible for allocation — for as long as the cleaner is reading out
    /// of it. Releasing as it went would let a log open the very segment being
    /// cleaned and write over blocks not copied yet.
    /// # C: O(BLKSIZE)
    pub(crate) fn migrate_data(&mut self, addr: u32, s: &Summary) -> Result<(), Errno> {
        let n = self.read_node(s.nid, None)?;
        let o = owner_of(&n.footer);
        let ofs = s.ofs_in_node as usize;
        let inode = self.read_inode(o.ino)?;
        let dir = crate::mode::file_type(inode.mode) == vfs::FileType::Directory;
        let data = self.read_main_block(addr)?;
        // Charged twice, to two different questions. It is a data block read,
        // which is what the file-data figure counts; it is also a block the
        // CLEANER read, which is the figure that says how much of the volume's
        // read traffic is the cleaner's own work rather than anyone's request.
        {
            use crate::stats::iostat::Io;
            self.io_account(Io::FsDataRead, BLKSIZE as u64, false);
            self.io_account(Io::FsGdataRead, BLKSIZE as u64, false);
            self.io_read_folio(0);
        }
        // An ahead-of-demand pass on a mount that places by age puts what it
        // moves in a log of its own. These blocks are old — that is why they
        // were chosen — and appending them to the log a live writer is filling
        // would make that section look part-old and part-new, so neither age
        // describes it and the next pass costs it wrongly.
        let kind = if self.segstate.gc_atgc_log { Kind::AtgcData }
                   else if dir { Kind::DirData } else { Kind::FileData };
        let new = self.write_data_kind(kind, s.nid, s.ofs_in_node, NULL_ADDR, &data)?;
        self.set_holder_addr(o.ino, o.holder, ofs, new)
    }

    /// Copy the node block at `addr` into a log.
    ///
    /// A node's owner is the node table, and the ordinary node write already
    /// records the new address there, so there is no second owner to repoint.
    /// That same write releases the old block, which is why a node victim
    /// needs no deferred release.
    ///
    /// PLACED at once rather than left dirty, which is what a foreground clean
    /// does in the reference: the whole point of the move is to empty the
    /// victim, and a node still in the mapping has not left it. A background
    /// clean may leave it dirty; this cleaner is only ever the foreground one,
    /// because it is what a caller with no room left is waiting on.
    /// # C: O(BLKSIZE)
    pub(crate) fn migrate_node(&mut self, nid: u32) -> Result<(), Errno> {
        let n = self.read_node(nid, None)?;
        let kind = self.migrated_node_kind(&n.footer)?;
        self.write_node(nid, n.footer.ino, n.block, kind)?;
        self.writeback_node(nid)?;
        Ok(())
    }

    /// The log a migrated node belongs in.
    ///
    /// The same choice the node's first write made: a node holding addresses
    /// follows its file's temperature, and one holding node ids is cold
    /// because it changes only when the file's shape does.
    /// # C: O(1 block)
    fn migrated_node_kind(&self, f: &Footer) -> Result<Kind, Errno> {
        if !live::holds_addresses(f.ofs_of_node()) { return Ok(Kind::IndirectNode); }
        let inode = self.read_inode(f.ino)?;
        Ok(self.node_kind(inode.mode))
    }
}
