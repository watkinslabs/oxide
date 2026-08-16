//! Opening a span, and the nameless inode it collects blocks in.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::F2FS_COMPR_FL;
use crate::mode;
use crate::uapi::*;
use crate::volume::curseg::Kind;
use crate::volume::dnode::{put32, put64};
use crate::volume::{NewInode, Volume};

use super::policy::{self, AtomicFacts, AtomicGate, StartAction};
use super::state::AtomicFile;

impl<S: SectorSource> Volume<S> {
    /// What the inode and the volume contribute to the START decision.
    /// # C: O(1 block)
    pub fn atomic_facts(&self, ino: u32) -> Result<AtomicFacts, Errno> {
        let inode = self.read_inode(ino)?;
        Ok(AtomicFacts {
            pinned: crate::pin::state::is_pinned(&inode),
            compressed_undisableable: inode.compressed() && inode.blocks > 1,
            already_atomic: self.is_atomic_file(ino),
        })
    }

    /// The gate facts this crate can answer on its own.
    ///
    /// A caller holding a file description fills in the three it owns; the
    /// two that come off the inode and the mount are answered here so they
    /// cannot drift from what the rest of the volume believes.
    /// # C: O(1 block)
    pub fn atomic_gate(&self, ino: u32) -> Result<AtomicGate, Errno> {
        let inode = self.read_inode(ino)?;
        Ok(AtomicGate {
            writable_handle: true,
            owner_or_capable: true,
            is_reg: mode::file_type(inode.mode) == vfs::FileType::Regular,
            o_direct: false,
            ro_mount: !self.writable,
        })
    }

    /// Open a span over `ino`.
    ///
    /// `replace` is the difference between the two START commands: an ordinary
    /// span leaves the file's existing blocks in place and overwrites the ones
    /// it writes, while a replacing span makes the commit discard everything
    /// the span did not write. The file's size goes to zero immediately in the
    /// second case — the writer is entitled to see an empty file — but its
    /// blocks are kept until the commit, because an abort has to put them back.
    /// # C: O(1 block), plus the inline conversion when there is one
    pub fn start_atomic_write(&mut self, ino: u32, replace: bool) -> Result<(), Errno> {
        let gate = self.atomic_gate(ino)?;
        let facts = self.atomic_facts(ino)?;
        if policy::start_atomic_write(&gate, &facts)? == StartAction::AlreadyOpen {
            return Ok(());
        }
        // A compressed file with nothing compressed stored stops being
        // compressed: the span writes plain blocks, and a commit that moved
        // them under a compressed inode would hand the cluster reader blocks
        // that are not a cluster.
        if self.read_inode(ino)?.compressed() {
            self.stamp_inode(ino, |b| {
                let flags = le32(b, I_FLAGS).unwrap_or(0) & !F2FS_COMPR_FL;
                put32(b, I_FLAGS, flags);
            })?;
        }
        // The span's blocks are addressed by index, so the file's first block
        // has to BE a block rather than bytes inside the inode.
        self.convert_inline(ino)?;
        let size = self.read_inode(ino)?.size;
        let cow = self.create_cow_inode(ino)?;
        self.atomic.insert(ino, AtomicFile::new(cow, size, replace));
        let visible = if replace { 0 } else { size };
        if replace { self.stamp_inode(ino, |b| put64(b, I_SIZE, 0))?; }
        self.stamp_inode(cow, |b| put64(b, I_SIZE, visible))?;
        Ok(())
    }

    /// Make the nameless inode a span collects its blocks in.
    ///
    /// It is an ORPHAN from the moment it exists. Nothing names it, so a crash
    /// leaves an inode no directory reaches; the orphan list is what lets the
    /// next mount find it and hand its blocks back instead of counting them
    /// live forever.
    ///
    /// Its owners are the file's rather than the caller's, because every block
    /// it holds is destined for the file and charging them to one identity and
    /// then moving them to another would make the commit a quota transfer.
    /// # C: O(1 block)
    fn create_cow_inode(&mut self, ino: u32) -> Result<u32, Errno> {
        self.writable_or_err()?;
        let src = self.read_inode(ino)?;
        let cow = self.alloc_nid()?;
        let spec = NewInode {
            mode: mode::S_IFREG | (src.mode & mode::PERM_MASK),
            uid: src.uid,
            gid: src.gid,
            rdev: 0,
            now: (self.clock, 0),
        };
        let mut block = self.blank_inode(cow, &spec, 0);
        put32(&mut block, I_PINO, src.pino);
        self.write_node(cow, cow, block, Kind::FileNode)?;
        self.valid_inode_count += 1;
        self.charge_inode(cow)?;
        self.open_inode(cow);
        self.add_orphan(cow)?;
        Ok(cow)
    }
}
