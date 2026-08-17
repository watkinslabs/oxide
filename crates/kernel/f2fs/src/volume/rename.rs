//! Moving a name, in all three forms the interface asks for.
//!
//! Three requests share one entry point because they share one hazard: every
//! one of them changes two directories and up to two inodes, and a failure
//! part way through leaves a name pointing at nothing or an inode nothing
//! names. So each form does its allocating FIRST — the whiteout's inode, the
//! room a replaced victim's removal needs — and only then rewrites entries.
//!
//! A flag this filesystem does not answer for is REFUSED, never dropped.
//! Silently ignoring `RENAME_EXCHANGE` reports success for an atomic swap
//! that did not happen, and the caller's next step assumes it did.

use syscall::errno::Errno;

use sectors::SectorSource;

use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};

use crate::flags::{FADVISE_LOST_PINO_BIT, FT_DIR};
use crate::limits::F2FS_LINK_MAX;
use crate::mode;
use crate::uapi::*;

use super::dnode::{put32, put64};
use super::namei::NewInode;
use super::Volume;

/// Every flag this filesystem answers for. One that is not here is refused.
pub const SUPPORTED_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;

/// The permission bits a whiteout carries: none. What identifies it is its
/// TYPE and its device number, and any permission would make it look like a
/// device node somebody meant to be usable.
const WHITEOUT_MODE: u16 = 0;

/// The device number a whiteout carries. Zero is not a device, which is the
/// point: nothing can be opened through it.
const WHITEOUT_DEV: u32 = 0;

/// One rename request: what moves, in which form, and on whose behalf.
///
/// A struct rather than a parameter list because the owner is read by exactly
/// one of the three forms — the whiteout a `RENAME_WHITEOUT` leaves behind is a
/// new inode and needs an identity to belong to — and a positional argument
/// nobody can name is how that gets passed wrongly.
#[derive(Clone, Debug)]
pub struct Rename<'a> {
    pub from: u32,
    pub old: &'a [u8],
    pub to: u32,
    pub new: &'a [u8],
    /// `RENAME_*`, as the interface defines them.
    pub flags: u32,
    /// Who owns a whiteout this rename creates. Unread by the other forms.
    pub owner: (u32, u32),
    pub now: (u64, u32),
}

/// A name that names a directory's own position rather than an entry in it.
/// # C: O(1)
fn is_dots(name: &[u8]) -> bool { name == b"." || name == b".." }

impl<S: SectorSource> Volume<S> {
    /// Move a name, exchange two, or move one and leave a whiteout behind.
    ///
    /// The flag check comes before every other refusal, including the ones
    /// about the names themselves: an unknown flag says the caller and this
    /// filesystem disagree about what was even asked for, and answering the
    /// rest of the request would be answering a different question.
    /// # C: O(depth) blocks
    pub fn rename(&mut self, r: &Rename<'_>) -> Result<(), Errno> {
        if r.flags & !SUPPORTED_FLAGS != 0 { return Err(Errno::Einval); }
        // An exchange replaces both names, so neither "refuse to replace" nor
        // "leave a marker behind" has a meaning alongside it.
        if r.flags & RENAME_EXCHANGE != 0 && r.flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0 {
            return Err(Errno::Einval);
        }
        self.writable_or_err()?;
        if is_dots(r.old) || is_dots(r.new) { return Err(Errno::Einval); }
        if r.flags & RENAME_EXCHANGE != 0 { self.cross_rename(r) } else { self.plain_rename(r) }
    }

    /// Move one name onto another, replacing whatever was there.
    /// # C: O(depth) blocks
    fn plain_rename(&mut self, r: &Rename<'_>) -> Result<(), Errno> {
        let (from, to, now) = (r.from, r.to, r.now);
        let from_inode = self.read_inode(from)?;
        let hit = self.lookup(&from_inode, from, r.old)?;
        let moving = self.read_inode(hit.ino)?;
        let moving_is_dir = mode::file_type(moving.mode) == vfs::FileType::Directory;
        let to_inode = self.read_inode(to)?;
        let victim = match self.lookup(&to_inode, to, r.new) {
            Ok(existing) => {
                if r.flags & RENAME_NOREPLACE != 0 { return Err(Errno::Eexist); }
                if existing.ino == hit.ino { return Ok(()); }
                let v = self.read_inode(existing.ino)?;
                let victim_is_dir = mode::file_type(v.mode) == vfs::FileType::Directory;
                if victim_is_dir && !self.dir_is_empty(&v, existing.ino)? {
                    return Err(Errno::Enotempty);
                }
                if victim_is_dir != moving_is_dir {
                    return Err(if victim_is_dir { Errno::Eisdir } else { Errno::Enotdir });
                }
                Some((existing.ino, victim_is_dir))
            }
            Err(_) => None,
        };
        // Both directories, and the name being replaced if there is one. Those
        // are the three identities a move charges — the reference names exactly
        // these and not the moved inode, whose own blocks do not change hands.
        // Acquired here, after every refusal and before the first allocation,
        // so a refused rename has read nothing and a proceeding one charges
        // records it already holds.
        self.dquot_initialize_pair(from, to)?;
        if let Some((victim_ino, _)) = victim { self.dquot_initialize(victim_ino)?; }
        // Every refusal above happens before anything is allocated or removed,
        // so a refused rename leaves both directories exactly as they were —
        // and the whiteout's inode is not taken until the request is certain.
        let whiteout = self.new_whiteout(r)?;
        if let Some((_, victim_is_dir)) = victim {
            if let Err(e) = self.remove(to, r.new, victim_is_dir, now) {
                if let Some(w) = whiteout { let _ = self.release_orphan(w); }
                return Err(e);
            }
        }
        self.move_entry(r, &hit, moving_is_dir, whiteout)
    }

    /// Take the name off the source, put it on the destination, and repair
    /// everything that named either side. # C: O(depth) blocks
    fn move_entry(&mut self, r: &Rename<'_>, hit: &super::DirEntry, moving_is_dir: bool,
                  whiteout: Option<u32>) -> Result<(), Errno> {
        let (from, to, now) = (r.from, r.to, r.now);
        let done = self.move_entry_inner(r, hit, moving_is_dir, whiteout);
        if done.is_err() {
            // The whiteout's inode was taken and nothing will ever name it.
            // Handing it back here is what keeps a refused rename from leaking
            // an inode per attempt.
            if let Some(w) = whiteout { let _ = self.release_orphan(w); }
            return done;
        }
        self.touch(from, now)?;
        if from != to { self.touch(to, now)?; }
        Ok(())
    }

    /// # C: O(depth) blocks
    fn move_entry_inner(&mut self, r: &Rename<'_>, hit: &super::DirEntry, moving_is_dir: bool,
                        whiteout: Option<u32>) -> Result<(), Errno> {
        let (from, to, now) = (r.from, r.to, r.now);
        self.remove_dentry(from, r.old)?;
        self.add_dentry(to, r.new, hit.ino, hit.file_type)?;
        if moving_is_dir && from != to {
            // The moved directory's own second entry names its parent, and a
            // stale one sends every walk back to the wrong place.
            self.set_dentry(hit.ino, b"..", to, FT_DIR, now)?;
            let up = self.read_inode(from)?.links.saturating_sub(1).max(1);
            self.stamp_inode(from, |b| put32(b, I_LINKS, up))?;
            let down = self.read_inode(to)?.links.saturating_add(1);
            self.stamp_inode(to, |b| put32(b, I_LINKS, down))?;
        }
        // A DIRECTORY's recorded parent is corrected, because a checker reads
        // it and a replay restores the entry from it. Anything else gets the
        // mark that says the recorded parent is no longer to be trusted: its
        // old name is gone, so a chain replay that re-created the entry from
        // this field would put the file back under a name that no longer
        // exists. A directory moved out from under a whiteout is in the same
        // position — the marker now holds its old name.
        let trust_pino = moving_is_dir && whiteout.is_none();
        let advise = self.read_inode(hit.ino)?.advise;
        self.stamp_inode(hit.ino, |b| {
            if trust_pino { put32(b, I_PINO, to); }
            else { b[I_ADVISE] = advise | FADVISE_LOST_PINO_BIT; }
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })?;
        // The marker takes the name the move vacated, and takes it through the
        // ordinary link path: that is what lifts it off the orphan list and
        // gives it its one link, in the one place those two happen together.
        if let Some(w) = whiteout { self.link(from, r.old, w, now)?; }
        // The name's DESTINATION is the half a removal does not cover. The
        // source directory was recorded when its entry was cleared; the
        // destination gained an entry that a chain replay would have to add
        // back, and a moved directory carries its own second entry with it.
        if self.opts.fsync_mode == crate::opts::FsyncMode::Strict {
            self.ino_lists.add(crate::checkpoint::InoKind::TransDir, to);
            if moving_is_dir { self.ino_lists.add(crate::checkpoint::InoKind::TransDir, hit.ino); }
        }
        Ok(())
    }

    /// The unnamed inode a `RENAME_WHITEOUT` will leave at the source name, or
    /// nothing when the request did not ask for one.
    ///
    /// A whiteout is a character device with no permissions and a device number
    /// of zero, which is what the layering filesystems above read as "the name
    /// below this one is deleted". It is created BEFORE the move so a volume
    /// with no room left refuses the whole request rather than completing the
    /// move and then failing to mark it.
    /// # C: O(1 block)
    fn new_whiteout(&mut self, r: &Rename<'_>) -> Result<Option<u32>, Errno> {
        if r.flags & RENAME_WHITEOUT == 0 { return Ok(None); }
        let spec = NewInode {
            mode: mode::S_IFCHR | WHITEOUT_MODE,
            uid: r.owner.0,
            gid: r.owner.1,
            rdev: WHITEOUT_DEV,
            now: r.now,
        };
        self.tmpfile(r.from, &spec).map(Some)
    }

    /// Exchange two existing names, each keeping its own inode's identity.
    ///
    /// Neither side is removed and neither link count changes: the two entries
    /// swap what they point at. The only counts that move are the PARENTS',
    /// and only when the pair is mixed — a directory arriving in a parent
    /// brings a second link with it and a file arriving does not.
    /// # C: O(depth) blocks
    fn cross_rename(&mut self, r: &Rename<'_>) -> Result<(), Errno> {
        let (from, to, now) = (r.from, r.to, r.now);
        if from == to && r.old == r.new { return Ok(()); }
        let from_inode = self.read_inode(from)?;
        let a = self.lookup(&from_inode, from, r.old)?;
        let to_inode = self.read_inode(to)?;
        // An exchange needs BOTH names. A destination that does not exist is
        // not a rename with nothing to replace — there is nothing to swap
        // with, which is a different answer from the one a plain move gives.
        let b = self.lookup(&to_inode, to, r.new)?;
        if a.ino == b.ino { return Ok(()); }
        let a_is_dir = mode::file_type(self.read_inode(a.ino)?.mode) == vfs::FileType::Directory;
        let b_is_dir = mode::file_type(self.read_inode(b.ino)?.mode) == vfs::FileType::Directory;
        let mixed = from != to && a_is_dir != b_is_dir;
        if mixed {
            // The parent that receives the directory gains a link. Checking the
            // ceiling before the swap is what stops a count from wrapping —
            // past the maximum it would read as a directory with no parents.
            let gaining = if a_is_dir { to } else { from };
            if self.read_inode(gaining)?.links >= F2FS_LINK_MAX { return Err(Errno::Emlink); }
        }
        // The two parents, and only they: an exchange moves no blocks between
        // inodes and changes no link count on either swapped file, so the
        // reference acquires for the directories alone.
        self.dquot_initialize_pair(from, to)?;
        // Both entries are rewritten IN PLACE, so neither name has to find room
        // and neither side can be lost to a full volume half way through.
        self.set_dentry(from, r.old, b.ino, b.file_type, now)?;
        self.set_dentry(to, r.new, a.ino, a.file_type, now)?;
        if from != to {
            if a_is_dir { self.set_dentry(a.ino, b"..", to, FT_DIR, now)?; }
            if b_is_dir { self.set_dentry(b.ino, b"..", from, FT_DIR, now)?; }
            self.repoint(a.ino, a_is_dir, to, now)?;
            self.repoint(b.ino, b_is_dir, from, now)?;
            if mixed {
                let (up, down) = if a_is_dir { (from, to) } else { (to, from) };
                let n = self.read_inode(up)?.links.saturating_sub(1).max(1);
                self.stamp_inode(up, |b| put32(b, I_LINKS, n))?;
                let n = self.read_inode(down)?.links.saturating_add(1);
                self.stamp_inode(down, |b| put32(b, I_LINKS, n))?;
            }
        }
        if self.opts.fsync_mode == crate::opts::FsyncMode::Strict {
            self.ino_lists.add(crate::checkpoint::InoKind::TransDir, from);
            self.ino_lists.add(crate::checkpoint::InoKind::TransDir, to);
        }
        Ok(())
    }

    /// Record where an exchanged inode now lives: the field for a directory,
    /// the mark that the field is stale for anything else. # C: O(1 block)
    fn repoint(&mut self, ino: u32, is_dir: bool, parent: u32, now: (u64, u32))
        -> Result<(), Errno> {
        let advise = self.read_inode(ino)?.advise;
        self.stamp_inode(ino, |b| {
            if is_dir { put32(b, I_PINO, parent); }
            else { b[I_ADVISE] = advise | FADVISE_LOST_PINO_BIT; }
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })
    }
}

#[cfg(test)]
#[path = "../tests/rename.rs"]
mod tests;
