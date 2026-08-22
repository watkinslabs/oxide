//! Creating, removing and renaming names.
//!
//! Every one of these changes TWO inodes — the directory and the thing named —
//! and the order matters. A new inode is written before its name is, so a
//! crash between the two leaves an unreachable inode rather than a name
//! pointing at nothing; and a name is removed before its inode's link count
//! drops, so the same crash leaves a link count too high rather than a live
//! name pointing at freed space. Both are the direction the reference chose,
//! and both are the direction a checker can repair.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::*;
use crate::mode;
use crate::uapi::*;

use super::dnode::{put32, put64};
use super::Volume;

/// What a removal did, for the layer that owns the rest of the lifecycle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Removed {
    /// The inode that lost the name.
    pub ino: u32,
    /// Its stored link count now. Zero means it is PARKED, not freed.
    pub links: u32,
}

impl Removed {
    /// Whether the removal took the last name and the inode is on the list.
    /// # C: O(1)
    pub fn parked(&self) -> bool { self.links == 0 }
}

/// What a new inode is being made as.
#[derive(Clone, Debug)]
pub struct NewInode {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    /// The device a special file names, in the interface's encoding.
    pub rdev: u32,
    /// Seconds and nanoseconds every timestamp is stamped with.
    pub now: (u64, u32),
}

impl<S: SectorSource> Volume<S> {
    /// Build a fresh inode block for `ino`. # C: O(BLKSIZE)
    pub(crate) fn blank_inode(&self, ino: u32, spec: &NewInode, links: u32) -> Vec<u8> {
        let mut b = vec![0u8; BLKSIZE];
        let extra = if crate::features::has_extra_attr(self.sb.feature) {
            TOTAL_EXTRA_ATTR_SIZE
        } else {
            0
        };
        let inline = if extra > 0 { EXTRA_ATTR } else { 0 };
        b[I_INLINE] = inline;
        super::dnode::put16(&mut b, I_MODE, spec.mode);
        put32(&mut b, I_UID, spec.uid);
        put32(&mut b, I_GID, spec.gid);
        put32(&mut b, I_LINKS, links);
        put64(&mut b, I_SIZE, 0);
        put64(&mut b, I_BLOCKS, 1);
        for (sec_at, nsec_at) in
            [(I_ATIME, I_ATIME_NSEC), (I_CTIME, I_CTIME_NSEC), (I_MTIME, I_MTIME_NSEC)]
        {
            put64(&mut b, sec_at, spec.now.0);
            put32(&mut b, nsec_at, spec.now.1);
        }
        put32(&mut b, I_GENERATION, ino);
        if extra > 0 {
            super::dnode::put16(&mut b, I_EXTRA_ISIZE, extra as u16);
            // A volume carrying the flexible bit states the reservation PER
            // INODE, so the mount line's `inline_xattr_size=` is what it means:
            // reserving the format's own number regardless would make the
            // option a value nothing reads. Without the bit the reservation is
            // fixed and the option has nowhere to be recorded.
            let reserve = if crate::features::has_flexible_inline_xattr(self.sb.feature) {
                self.opts.inline_xattr_addrs()
            } else {
                0
            };
            super::dnode::put16(&mut b, I_INLINE_XATTR_SIZE, reserve);
            put64(&mut b, I_CRTIME, spec.now.0);
            put32(&mut b, I_CRTIME_NSEC, spec.now.1);
        }
        b
    }

    /// Make a new inode of any kind and link it into `dir` as `name`.
    ///
    /// The one entry point for create, mkdir, symlink and mknod: they differ
    /// only in the mode, the initial contents and the link counts, and having
    /// four copies of the ordering above is how one of them ends up wrong.
    ///
    /// The compression policy is NOT offered the name here. That is the split
    /// the reference draws and it is not arbitrary: a name only says something
    /// about the bytes a file will hold when the caller creating it meant the
    /// name to describe them. A device node, a symbolic link and an unnamed
    /// temporary file carry names that describe nothing of the sort, so they
    /// take compression from neither their name nor their directory.
    /// # C: O(depth) blocks
    pub fn create(&mut self, dir: u32, name: &[u8], spec: &NewInode, body: Option<&[u8]>)
        -> Result<u32, Errno> {
        self.create_inner(dir, name, spec, body, false)
    }

    /// The ordinary file-creation form, which DOES offer the name.
    /// # C: O(depth) blocks
    pub fn create_named(&mut self, dir: u32, name: &[u8], spec: &NewInode, body: Option<&[u8]>)
        -> Result<u32, Errno> {
        self.create_inner(dir, name, spec, body, true)
    }

    /// # C: O(depth) blocks
    fn create_inner(&mut self, dir: u32, name: &[u8], spec: &NewInode, body: Option<&[u8]>,
                    named: bool) -> Result<u32, Errno> {
        self.writable_or_err()?;
        let parent = self.read_inode(dir)?;
        if mode::file_type(parent.mode) != vfs::FileType::Directory { return Err(Errno::Enotdir); }
        if self.lookup(&parent, dir, name).is_ok() { return Err(Errno::Eexist); }
        // Both identities this creation will charge — the directory that gains
        // a name and the file that is about to exist — are acquired here,
        // before anything is written. Every charge below then operates on
        // records already held, so no allocation reads a quota file from
        // underneath the node write it is part of.
        self.dquot_initialize(dir)?;
        self.dquot_initialize_new(spec.uid, spec.gid)?;
        // The parent's key, once, before an id is taken or a block is built.
        // The name this inode RECORDS has to be the form the medium holds —
        // ciphertext when the parent encrypts — so the key is needed here and
        // not only where the entry is placed. Refusing before `alloc_nid` also
        // means a locked directory leaves no id handed out; the reference
        // prepares the new inode's encryption at the same point, before its
        // inode exists.
        let dir_crypt = self.crypt_require_key(&parent, dir)?;
        let ft = mode::file_type(spec.mode);
        let is_dir = ft == vfs::FileType::Directory;
        // The inode record itself, from the cache the reference keeps them in,
        // and BEFORE the node id is taken — its order, so an injected failure
        // here leaves no id handed out and nothing to give back.
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::SlabAlloc) {
            return Err(Errno::Enomem);
        }
        let ino = self.alloc_nid()?;
        // The number the request's identity belongs to is known now, so the
        // attachment is made before the first thing that could charge it.
        self.dquot_attach(ino, crate::volume::quotas::Owners::new(
            spec.uid, spec.gid, crate::volume::quotas::DEFAULT_PROJID));
        let mut block = self.blank_inode(ino, spec, if is_dir { 2 } else { 1 });
        put32(&mut block, I_PINO, dir);
        // THE STORED FORM, not the plaintext. This field is what a replay reads
        // to put a lost directory entry back, and a replay runs at mount with no
        // key — so a plaintext name here is a name recovery cannot turn into an
        // entry, and it also writes an encrypted file's name onto the medium in
        // the clear.
        let stored: Vec<u8> = match &dir_crypt {
            Some(c) => c.encrypt_name(name).map_err(|e| e.errno())?,
            None => Vec::from(name),
        };
        let namelen = stored.len().min(NAME_LEN);
        put32(&mut block, I_NAMELEN, namelen as u32);
        block[I_NAME..I_NAME + namelen].copy_from_slice(&stored[..namelen]);
        if let Some(c) = &dir_crypt {
            // Recorded so another reader knows the field is not a name it can
            // print. Its only use in the reference is exactly that.
            block[I_ADVISE] |= FADVISE_ENC_NAME_BIT;
            // A directory that also folds files its entries under a KEYED hash
            // of the folded plaintext, which no keyless replay can compute. The
            // value is written after the name, where recovery reads it back; if
            // it does not fit, the inode is marked as having lost its parent
            // instead, which sends a later `fsync` down the checkpoint path so
            // no replay ever needs the hash.
            if parent.casefolded() {
                let want = self.entry_hash_crypt(&parent, Some(c), name)?;
                if namelen + core::mem::size_of::<u32>() <= NAME_LEN {
                    put32(&mut block, I_NAME + namelen, want);
                } else {
                    block[I_ADVISE] |= FADVISE_LOST_PINO_BIT;
                }
            }
        }
        // Before the inline offer below, never after. A compressed file's
        // blocks are clusters and its inline region would be read as plain
        // bytes, so the two are mutually exclusive — and only the compression
        // decision can say which of them the file gets.
        let compressed =
            self.stamp_new_compress(&mut block, parent.flags, is_dir,
                                    if named { Some(name) } else { None });
        if is_dir {
            block[I_INLINE] |= INLINE_DENTRY | INLINE_DATA | DATA_EXIST;
            put32(&mut block, I_CURRENT_DEPTH, 1);
        } else if !compressed
            // Inline bytes have no data-unit address for fscrypt to derive an
            // IV from. Linux excludes an encrypted regular file here too.
            && dir_crypt.is_none()
            && self.opts.inline_data
            && matches!(ft, vfs::FileType::Regular | vfs::FileType::Symlink)
        {
            // A small file starts INSIDE its inode, which is where most files
            // on a real volume stay. The data-exists mark waits for the first
            // write: the region still holds the address array's old bytes.
            block[I_INLINE] |= INLINE_DATA;
        }
        if mode::has_rdev(spec.mode) {
            // The narrow slot stays zero so the wide one is what is read; the
            // narrow form cannot carry a minor past a byte.
            let base = OFFSET_OF_END_OF_I_EXT
                + le16(&block, I_EXTRA_ISIZE).unwrap_or(0) as usize;
            put32(&mut block, base + 4, spec.rdev);
        }
        self.write_node(ino, ino, block, self.node_kind(spec.mode))?;
        // Linux prepares the policy before allocating the inode, then stores
        // the resulting fresh context with the inode metadata before the name
        // is published. The parent's held record is the prepared policy here:
        // it was resolved above, before `alloc_nid`, and no second xattr read
        // is needed. Special files deliberately remain plaintext, just as
        // `fscrypt_prepare_new_inode` requires.
        if matches!(ft,
            vfs::FileType::Regular | vfs::FileType::Directory | vfs::FileType::Symlink)
        {
            let child = self.read_inode(ino)?;
            let facts = self.crypt_inode_facts(&child);
            let fs = self.crypt_fs_facts(&child);
            if let Some(ctx) = crate::crypto::inherit::context_for_new(
                dir_crypt.as_deref(), &facts, &fs, self.fresh_nonce(ino),
            ).map_err(|e| e.errno())? {
                self.crypt_store_new_context(ino, &ctx)?;
            }
        }
        self.valid_inode_count += 1;
        self.charge_inode(ino)?;
        if is_dir { self.init_dir(ino, dir)?; }
        if let Some(bytes) = body { self.write_file(ino, 0, bytes)?; }
        // The name goes down last: a crash before it leaves an unreachable
        // inode, which a check reclaims, rather than a name pointing at
        // nothing, which it cannot.
        self.add_dentry(dir, name, ino, ftype_byte(spec.mode))?;
        if is_dir {
            let links = self.read_inode(dir)?.links.saturating_add(1);
            self.stamp_inode(dir, |b| put32(b, I_LINKS, links))?;
        }
        self.touch(dir, spec.now)?;
        Ok(ino)
    }

    /// Give a new directory its own two entries. # C: O(1 block)
    fn init_dir(&mut self, ino: u32, parent: u32) -> Result<(), Errno> {
        self.add_dentry(ino, b".", ino, FT_DIR)?;
        self.add_dentry(ino, b"..", parent, FT_DIR)
    }

    /// Remove a name. `expect_dir` says which of unlink and rmdir was asked
    /// for, and a mismatch is refused rather than silently done.
    ///
    /// Reports which inode lost the name and what its stored link count is now,
    /// because the layer above owns the rest of the lifecycle: at zero the
    /// inode is PARKED here and only that layer knows whether anything still
    /// holds it, so only it can decide whether the eviction happens now or when
    /// the last handle goes.
    /// # C: O(depth) blocks
    pub fn remove(&mut self, dir: u32, name: &[u8], expect_dir: bool, now: (u64, u32))
        -> Result<Removed, Errno> {
        self.writable_or_err()?;
        if name == b"." || name == b".." { return Err(Errno::Einval); }
        let parent = self.read_inode(dir)?;
        let hit = self.lookup(&parent, dir, name)?;
        let victim = self.read_inode(hit.ino)?;
        let victim_is_dir = mode::file_type(victim.mode) == vfs::FileType::Directory;
        if expect_dir && !victim_is_dir { return Err(Errno::Enotdir); }
        if !expect_dir && victim_is_dir { return Err(Errno::Eisdir); }
        if victim_is_dir && !self.dir_is_empty(&victim, hit.ino)? { return Err(Errno::Enotempty); }
        // A removal gives space back on two identities — the directory losing
        // an entry and the file losing its blocks — so both records are in hand
        // before either is touched.
        self.dquot_initialize(dir)?;
        self.dquot_initialize(hit.ino)?;
        // Room for the parking is claimed while the directory is still intact.
        // Every removal asks, not only the one taking the last name: a list
        // with no room left cannot record a debt, and a removal that discovers
        // that after taking the entry out has an inode it can neither park nor
        // reach. Refused here, the caller's directory is untouched and the
        // refusal is one it can act on.
        self.reserve_orphan()?;
        self.remove_dentry(dir, name)?;
        // The link count goes down and the inode is PARKED when it reaches
        // zero — never freed here. A descriptor may still be reading it, and
        // eviction is the point that knows one is not.
        self.drop_nlink(dir, hit.ino, victim_is_dir, now)?;
        self.touch(dir, now)?;
        Ok(Removed { ino: hit.ino, links: self.read_inode(hit.ino)?.links })
    }

    /// Give an existing file a second name — or a FIRST one, for an inode that
    /// has none.
    ///
    /// Both cases are here because they are the same operation on the medium
    /// and differ only in what the link count was. An inode at zero links is
    /// parked on the orphan list, so giving it a name has to lift it off:
    /// leaving it there means the next mount reclaims a file that is now
    /// reachable by name, which is a loss of live data rather than a leak.
    /// # C: O(depth) blocks
    pub fn link(&mut self, dir: u32, name: &[u8], ino: u32, now: (u64, u32))
        -> Result<(), Errno> {
        self.writable_or_err()?;
        let target = self.read_inode(ino)?;
        // A directory with two names is a loop the walk cannot escape, which
        // is why no filesystem allows one.
        if mode::file_type(target.mode) == vfs::FileType::Directory { return Err(Errno::Eperm); }
        let parent = self.read_inode(dir)?;
        if self.lookup(&parent, dir, name).is_ok() { return Err(Errno::Eexist); }
        // The directory gains an entry and may gain a block for it.
        self.dquot_initialize(dir)?;
        self.dquot_initialize(ino)?;
        self.add_dentry(dir, name, ino, ftype_byte(target.mode))?;
        // A file that gains a name can no longer have its OLD entry restored
        // from the recorded parent: the field now names one of several places
        // it is reachable from, and a replay that rebuilt an entry from it
        // would invent a name nobody created. The mark is what sends a later
        // `fsync` of this file down the checkpoint path instead.
        let advise = target.advise | FADVISE_LOST_PINO_BIT;
        let links = target.links.saturating_add(1);
        self.stamp_inode(ino, |b| {
            put32(b, I_LINKS, links);
            b[I_ADVISE] = advise;
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })?;
        // Coming off the orphan list is NOT done here. `add_dentry` above owns
        // it, for every caller that lands a name — a linked temporary file, a
        // whiteout taking a vacated name, a replay putting an entry back — and
        // a second unpark beside it would be a second answer to one question.
        self.touch(dir, now)
    }

    /// Stamp a directory's modification and change times. # C: O(1 block)
    pub(crate) fn touch(&mut self, ino: u32, now: (u64, u32)) -> Result<(), Errno> {
        self.stamp_inode(ino, |b| {
            put64(b, I_MTIME, now.0);
            put32(b, I_MTIME_NSEC, now.1);
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })
    }

    /// Change an inode's permission bits and identity. # C: O(1 block)
    pub fn set_attr(&mut self, ino: u32, mode_bits: Option<u16>, owner: Option<(u32, u32)>,
                    now: (u64, u32)) -> Result<(), Errno> {
        self.writable_or_err()?;
        // The identity this inode is charged against is about to change, so
        // BOTH the one losing it and the one gaining it have to be in hand.
        self.dquot_initialize(ino)?;
        if let Some((uid, gid)) = owner { self.dquot_initialize_new(uid, gid)?; }
        if let Some((uid, gid)) = owner {
            let projid = self.read_inode(ino)?.projid;
            self.dquot_transfer(ino, crate::volume::quotas::Owners::new(uid, gid, projid))?;
        }
        let cur = self.read_inode(ino)?.mode;
        self.stamp_inode(ino, |b| {
            if let Some(m) = mode_bits {
                super::dnode::put16(b, I_MODE, (cur & mode::S_IFMT) | (m & mode::PERM_MASK));
            }
            if let Some((uid, gid)) = owner {
                put32(b, I_UID, uid);
                put32(b, I_GID, gid);
            }
            put64(b, I_CTIME, now.0);
            put32(b, I_CTIME_NSEC, now.1);
        })?;
        // The inode's allocations are charged against its owners, so an owner
        // change moves which records they land on. Leaving the old attachment
        // would keep charging the identity that no longer owns the file.
        if let Some((uid, gid)) = owner {
            let projid = self.read_inode(ino)?.projid;
            self.dquot_attach(ino, crate::volume::quotas::Owners::new(uid, gid, projid));
        }
        Ok(())
    }

    /// Change an inode's stored times. # C: O(1 block)
    pub fn set_times(&mut self, ino: u32, atime: (u64, u32), mtime: (u64, u32))
        -> Result<(), Errno> {
        self.writable_or_err()?;
        self.stamp_inode(ino, |b| {
            put64(b, I_ATIME, atime.0);
            put32(b, I_ATIME_NSEC, atime.1);
            put64(b, I_MTIME, mtime.0);
            put32(b, I_MTIME_NSEC, mtime.1);
        })
    }
}

/// The type byte a directory entry stores for a mode. # C: O(1)
pub fn ftype_byte(mode_word: u16) -> u8 {
    match mode::file_type(mode_word) {
        vfs::FileType::Directory => FT_DIR,
        vfs::FileType::Symlink => FT_SYMLINK,
        vfs::FileType::CharDev => FT_CHRDEV,
        vfs::FileType::BlockDev => FT_BLKDEV,
        vfs::FileType::Fifo => FT_FIFO,
        vfs::FileType::Socket => FT_SOCK,
        vfs::FileType::Regular => FT_REG_FILE,
    }
}

#[cfg(test)]
#[path = "../tests/namei.rs"]
mod tests;
