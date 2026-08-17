//! Directory entries in the form the medium holds them.
//!
//! An entry's stored name is the ciphertext when the directory encrypts, and
//! the plaintext when it does not; its hash is whatever the format files it
//! under. A caller holding BOTH needs no key to place the entry or to find it,
//! and that is not a shortcut — it is the only way a replay can work, because a
//! replay runs at mount, over a directory whose key may never be added, and the
//! name it is putting back is already in stored form inside the recovered
//! inode.
//!
//! Reached from the entry-plus-key path above (`dirwrite`) and from the replay.
//! Keeping the two apart is what keeps the key resolution — an attribute read,
//! a node read and a page lock that can block — off the mount path.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::dirent::{block as deblock, bucket, Layout};
use crate::limits::MAX_LOOKUP_DEPTH;
use crate::node::Inode;
use crate::uapi::{dentry_slots, NAME_LEN};

use super::dirwrite::{place_entry_hashed, room_for};
use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Place an entry whose name is already in stored form, under the hash the
    /// caller filed it by.
    ///
    /// Every length decision is about the STORED bytes: an encrypted name and
    /// its plaintext differ in length, so sizing a record from the plaintext
    /// overflows the slot.
    /// # C: O(depth) blocks
    pub(crate) fn add_stored_dentry(&mut self, dir: u32, inode: &Inode, name: &[u8], want: u32,
                                    ino: u32, ft: u8) -> Result<(), Errno> {
        self.writable_or_err()?;
        if name.is_empty() || name.len() > NAME_LEN { return Err(Errno::Enametoolong); }
        let slots = dentry_slots(name.len());
        if inode.inline_dentry() {
            let (at, len) = inode.inline_data_span();
            let l = Layout::inline(len);
            let mut block = self.inode_bytes(dir)?;
            if let Some(slot) = room_for(&block[at..at + len], &l, slots) {
                place_entry_hashed(&mut block[at..at + len], &l, slot, name, want, ino, ft);
                self.put_inode(dir, block)?;
                self.unpark_orphan(ino);
                return Ok(());
            }
            self.convert_inline_dir(dir)?;
        }
        self.add_regular_dentry(dir, name, ino, ft, slots, want)?;
        // A name has landed. An inode parked for want of one — a file made
        // without a name and then linked to it, or one whose last name went
        // while something held it open and whose name a replay has just put
        // back — is reachable again, and a mount that still found it on the
        // orphan list would free a file that has a name.
        self.unpark_orphan(ino);
        Ok(())
    }

    /// The inode an entry with exactly these stored bytes names, or `None`.
    ///
    /// A byte-for-byte comparison of the stored name under the one bucket the
    /// hash names — no decryption, no folding, no rescan. That is what the
    /// reference's find does when it is handed a disk name, and it is
    /// deliberately NOT a lookup: a lookup takes a caller's spelling and has to
    /// decide what it could mean, and every one of those decisions needs a key.
    /// # C: O(depth) blocks
    pub(crate) fn find_stored_entry(&self, inode: &Inode, dir: u32, want: u32, name: &[u8])
        -> Result<Option<u32>, Errno> {
        if name.is_empty() || name.len() > NAME_LEN { return Err(Errno::Enametoolong); }
        if inode.inline_dentry() {
            let (area, layout) = self.inline_dir(inode, dir)?;
            let hit = deblock::find(&area, &layout, want, name).map_err(|_| Errno::Eio)?;
            return Ok(hit.map(|h| h.ino));
        }
        let l = Layout::block();
        let depth = inode.current_depth.min(MAX_LOOKUP_DEPTH);
        for level in 0..depth {
            for index in bucket::search_range(want, level, inode.dir_level) {
                let Some(area) = self.dir_block(inode, dir, index)? else { continue };
                let Some(hit) = deblock::find(&area, &l, want, name).map_err(|_| Errno::Eio)?
                    else { continue };
                return Ok(Some(hit.ino));
            }
        }
        Ok(None)
    }
}
