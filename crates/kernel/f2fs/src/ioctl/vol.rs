//! The volume operations the ioctl surface needs and that no other caller
//! has yet asked for.
//!
//! They live beside the surface that uses them rather than in the volume's
//! own modules because the ioctl is their only caller: a pin bit nothing sets
//! and a label nothing writes are the machinery-with-no-caller this project
//! keeps finding, and putting them here makes the caller obvious.

use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::flags::{FEATURE_ATOMIC_WRITE, PIN_FILE};
use crate::node::Inode;
use crate::uapi::{I_INLINE, SB_VOLUME_NAME_UNITS};
use crate::volume::Volume;

use super::uapi::FSLABEL_MAX;

impl<S: SectorSource> Volume<S> {
    /// The feature word a caller asking what this volume supports is told.
    ///
    /// The stored word plus atomic writes, which the format does not record
    /// as a feature because every volume has them, but which callers test for
    /// here.
    /// # C: O(1)
    pub fn ioctl_features(&self) -> u32 { self.sb.feature | FEATURE_ATOMIC_WRITE }

    /// Is `ino` pinned — its blocks fixed where they are, so the cleaner may
    /// not move them? # C: O(1 block)
    pub fn is_pinned(&self, ino: u32) -> Result<bool, Errno> {
        Ok(self.read_inode(ino)?.has(PIN_FILE))
    }

    /// Pin or unpin `ino`.
    ///
    /// Pinning is refused for a file that already holds blocks, because the
    /// promise is about where the blocks ARE and the ones already written
    /// went wherever the log put them.
    /// # C: O(1 block)
    pub fn set_pinned(&mut self, ino: u32, pin: bool) -> Result<(), Errno> {
        self.writable_or_err()?;
        let inode = self.read_inode(ino)?;
        if inode.has(PIN_FILE) == pin { return Ok(()); }
        if pin && inode.blocks > 1 { return Err(Errno::Efbig); }
        // Data still inside the inode has no address to fix, so it is moved
        // out to a block before the promise is made.
        if pin && inode.inline_data() { self.convert_inline(ino)?; }
        self.stamp_inode(ino, |b| {
            if pin { b[I_INLINE] |= PIN_FILE; } else { b[I_INLINE] &= !PIN_FILE; }
        })
    }

    /// The volume's label, as the medium holds it. # C: O(1)
    pub fn label(&self) -> &str { &self.sb.volume_name }

    /// Write a new label through to BOTH superblock copies.
    ///
    /// The label is the one piece of the superblock an ordinary tool changes
    /// while the volume is mounted, so it goes through the same two-copy
    /// commit a repair does: the copy that is not currently believed is
    /// written first, and a crash between the two leaves the volume mounting
    /// exactly as it did.
    /// # C: O(1 block) per copy
    pub fn set_label(&mut self, name: &str) -> Result<(), Errno> {
        self.writable_or_err()?;
        if name.encode_utf16().count() > SB_VOLUME_NAME_UNITS { return Err(Errno::Einval); }
        // The mount's OWN copy, not a fresh read: a second copy of the
        // superblock bytes could disagree with this one, and the flag word
        // records a write the medium refused so a later remount can pay it.
        crate::sbwrite::edit::set_volume_name(&mut self.sb_raw, name)?;
        let ro = !self.writable;
        if let Err(e) = crate::sbwrite::commit_super(&self.source, &mut self.sb_raw, false, ro,
                                                     &mut self.sbi) {
            // Put the edit back, so what the volume reports and what the
            // medium holds cannot disagree.
            let _ = crate::sbwrite::edit::set_volume_name(&mut self.sb_raw, &self.sb.volume_name);
            return Err(e);
        }
        self.adopt_super()
    }

    /// The label as the fixed-size buffer the query command hands back: the
    /// bytes, then a terminator, then zeroes. # C: O(label bytes)
    pub fn label_buffer(&self) -> Vec<u8> {
        let mut b = alloc::vec![0u8; FSLABEL_MAX as usize];
        let s = self.sb.volume_name.as_bytes();
        let n = s.len().min(FSLABEL_MAX as usize - 1);
        b[..n].copy_from_slice(&s[..n]);
        b
    }

    /// The password salt the superblock carries, generating one on first ask.
    ///
    /// The salt is written through before it is reported, because a caller
    /// that derived a key from a salt the volume then forgot would be unable
    /// to open its own files after a remount.
    /// # C: O(1 block) per copy on first ask
    pub fn encryption_pwsalt(&mut self, fresh: [u8; 16]) -> Result<[u8; 16], Errno> {
        let held = crate::sbwrite::edit::pw_salt(&self.sb_raw);
        if held.iter().any(|b| *b != 0) { return Ok(held); }
        self.writable_or_err()?;
        if !crate::sbwrite::edit::set_pw_salt(&mut self.sb_raw, &fresh) { return Err(Errno::Einval); }
        let ro = !self.writable;
        if let Err(e) = crate::sbwrite::commit_super(&self.source, &mut self.sb_raw, false, ro,
                                                     &mut self.sbi) {
            // A salt that is not on the medium must not exist: a caller would
            // derive a key from it and lose every file after a remount.
            let _ = crate::sbwrite::edit::set_pw_salt(&mut self.sb_raw, &[0u8; 16]);
            return Err(e);
        }
        self.adopt_super()?;
        Ok(fresh)
    }

    /// The blocks `ino`'s compressed clusters saved. # C: O(1 block)
    pub fn compress_blocks(&self, ino: u32) -> Result<u64, Errno> {
        Ok(self.read_inode(ino)?.compr_blocks)
    }

    /// The codec and cluster size `ino` was written under. # C: O(1 block)
    pub fn compress_option(&self, ino: u32) -> Result<(u8, u8), Errno> {
        let i = self.read_inode(ino)?;
        Ok((i.compress_algorithm, i.log_cluster_size))
    }

    /// Change the codec and cluster size `ino` will be written under.
    ///
    /// Only legal while the file holds no blocks: the cluster size decides
    /// what every stored address MEANS, so changing it under existing blocks
    /// would reinterpret them as a different grouping and read the file back
    /// as something else.
    /// # C: O(1 block)
    pub fn set_compress_option(&mut self, ino: u32, algorithm: u8, log_cluster_size: u8)
        -> Result<(), Errno> {
        self.writable_or_err()?;
        let inode = self.read_inode(ino)?;
        if inode.blocks > 1 { return Err(Errno::Efbig); }
        self.stamp_inode(ino, |b| {
            b[crate::uapi::I_COMPRESS_ALGORITHM] = algorithm;
            b[crate::uapi::I_LOG_CLUSTER_SIZE] = log_cluster_size;
        })
    }

    /// Walk `ino`'s whole index once so every extent it holds is resolved.
    ///
    /// The count is what the walk actually reached, which is how a caller
    /// tells a fully-cached file from one whose index stopped early.
    /// # C: O(file blocks)
    pub fn precache_extents(&self, inode: &Inode, ino: u32) -> Result<u64, Errno> {
        let blocks = inode.size.div_ceil(crate::uapi::BLKSIZE as u64);
        let mut reached = 0u64;
        for index in 0..blocks {
            match self.map_block(inode, ino, index) {
                Ok(_) => reached += 1,
                // A hole is part of the file's shape, not a failure to walk.
                Err(Errno::Enoent) => reached += 1,
                Err(e) => return Err(e),
            }
        }
        Ok(reached)
    }

    /// Replace the inode's stored flag word.
    ///
    /// The whole word, not a merge: the caller already decided which bits it
    /// may move, and a second merge here would be a second answer to that.
    ///
    /// The compression mark is NOT just a bit in that word. Adding it commits
    /// the file to a codec and a cluster width that have to be recorded with
    /// it — an inode marked compressed and carrying no width claims a width of
    /// zero, which the format does not admit and this crate's own inode check
    /// rejects, so the file stops being readable. Taking it away, or adding it
    /// to a file that already holds blocks, is refused for the mirror reason:
    /// the addresses already written mean one thing under the mark and another
    /// without it.
    /// # C: O(1 block), or a block move where inline data has to be converted
    pub fn set_inode_flags(&mut self, ino: u32, flags: u32) -> Result<(), Errno> {
        self.writable_or_err()?;
        let inode = self.read_inode(ino)?;
        let st = crate::compress::chattr::FileState {
            is_reg: crate::mode::file_type(inode.mode) == vfs::FileType::Regular,
            is_dir: crate::mode::file_type(inode.mode) == vfs::FileType::Directory,
            // The inode block itself is counted, so a file holding data holds
            // more than one.
            has_blocks: inode.blocks > 1,
            pinned: inode.has(crate::flags::PIN_FILE),
            atomic: self.is_atomic_file(ino),
        };
        let change =
            crate::compress::chattr::check(self.sb.feature, inode.flags, flags, &st)?;
        let setting = change == crate::compress::chattr::FlagChange::Set;
        let mut stamp = None;
        if setting {
            // The settings have nowhere to go on an inode too narrow to hold
            // them, and the mount may be running with a combination this build
            // cannot write. Both are refusals rather than a mark stamped with
            // nothing behind it.
            if crate::uapi::I_COMPRESS_FLAG + 2
                > crate::uapi::OFFSET_OF_END_OF_I_EXT + inode.extra_isize
            {
                return Err(Errno::Eopnotsupp);
            }
            let c = self.opts.compress;
            stamp = Some(
                crate::compress::policy::context(c.algorithm, c.log_size, c.chksum, c.level)
                    .ok_or(Errno::Einval)?,
            );
            // Before the mark goes down, not after: a file whose bytes live
            // inside its inode has no clusters to put them in, and the
            // conversion is what gives it the addresses the mark describes.
            if inode.inline_data() { self.convert_inline(ino)?; }
        }
        self.stamp_inode(ino, |b| {
            crate::volume::dnode::put32(b, crate::uapi::I_FLAGS, flags);
            if let Some((algo, log, flag)) = stamp {
                b[crate::uapi::I_COMPRESS_ALGORITHM] = algo;
                b[crate::uapi::I_LOG_CLUSTER_SIZE] = log;
                crate::volume::dnode::put16(b, crate::uapi::I_COMPRESS_FLAG, flag);
            }
        })
    }

    /// Set the change counter a caller reads back through the version query.
    /// # C: O(1 block)
    pub fn set_generation(&mut self, ino: u32, generation: u32) -> Result<(), Errno> {
        self.writable_or_err()?;
        self.stamp_inode(ino, |b| {
            crate::volume::dnode::put32(b, crate::uapi::I_GENERATION, generation);
        })
    }

    /// Does this mount hold the key a policy names? # C: O(log keys)
    pub fn holds_encryption_key(&self, id: &crate::crypto::KeyId) -> bool {
        self.fscrypt_keys.contains_key(id)
    }

    /// Give an empty directory the policy every file created under it will
    /// inherit.
    ///
    /// Only an empty directory: the policy decides how names and contents are
    /// written, so applying one to a directory that already holds entries
    /// would leave the existing ones written under no policy and unreadable
    /// once the key is added.
    /// # C: O(1 directory read + attribute write)
    pub fn set_encryption_policy(&mut self, ino: u32, wire: &[u8]) -> Result<(), Errno> {
        self.writable_or_err()?;
        // The policy is stored as an attribute, which may take a block.
        self.dquot_initialize(ino)?;
        let inode = self.read_inode(ino)?;
        let want = super::policy::parse_wire(wire).map_err(|e| e.errno())?;
        // THE EXISTING POLICY FIRST, before anything about what the inode is.
        // The reference's order, and it is observable: an inode that already
        // carries a context is answered about that context, so a non-directory
        // that somehow has one reports `EEXIST` rather than `ENOTDIR`. Deciding
        // `ENOTDIR` first would answer a question the caller did not ask.
        //
        // Re-applying the SAME policy is how a tool makes sure of one it may
        // already have set, and must not be an error; a DIFFERENT one is a
        // second answer to how the directory's children are written. A context
        // that is THERE but unrecognised is also `EEXIST`: it is a policy this
        // build cannot compare, which is not a policy it may overwrite.
        match self.crypt_context(&inode, ino) {
            Ok(Some(held)) => return if crate::crypto::policy::equal(&held.policy, &want) {
                Ok(())
            } else {
                Err(Errno::Eexist)
            },
            // Nothing stored yet. `EUCLEAN` is the same answer: it is an inode
            // whose flag says encrypted and which carries no context at all,
            // which the reference reads as "no policy" and gives one.
            Ok(None) | Err(Errno::Euclean) => {}
            Err(Errno::Einval) | Err(Errno::Enopkg) => return Err(Errno::Eexist),
            Err(e) => return Err(e),
        }
        let facts = self.crypt_inode_facts(&inode);
        if !facts.is_dir { return Err(Errno::Enotdir); }
        if !self.dir_is_empty(&inode, ino)? { return Err(Errno::Enotempty); }
        // Last, where the reference puts it: a caller that named a bad policy,
        // a file, a directory with a different policy or a non-empty one hears
        // about that first, and only a request that would otherwise have been
        // honoured is refused for what the volume promises a repair tool.
        if ino == self.root_ino()
            && !crate::crypto::support::root_may_be_encrypted(self.sb.feature) {
            return Err(Errno::Eperm);
        }
        let nonce = self.fresh_nonce(ino);
        let ctx = crate::crypto::policy::Context { policy: want, nonce };
        let (bytes, used) = crate::crypto::policy::serialize(&ctx);
        // The context is reached by INDEX rather than by a name a caller
        // could pass, so it is placed through the attribute list directly.
        let area = self.xattr_area(&inode, ino)?;
        let mut attrs = crate::xattr::list(&area).map_err(|_| Errno::Eio)?;
        attrs.push(crate::xattr::Attr {
            index: crate::uapi::XATTR_INDEX_ENCRYPTION,
            name: crate::crypto::uapi::XATTR_NAME.to_vec(),
            value: bytes[..used].to_vec(),
        });
        self.store_xattrs(ino, &attrs)?;
        self.stamp_inode(ino, |b| {
            let at = crate::uapi::I_FLAGS;
            let held = u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
            crate::volume::dnode::put32(b, at, held | crate::flags::F2FS_ENCRYPT_FL);
        })?;
        // The directory has a context now, so anything resolved for it before
        // this — under no policy — no longer describes it.
        self.crypt_forget(ino);
        Ok(())
    }

    /// A nonce for a newly encrypted inode.
    ///
    /// Derived from the volume's own identity and the inode number rather
    /// than from a generator this crate does not have, so two inodes on one
    /// volume never share one and two volumes never produce the same pair.
    /// # C: O(1)
    fn fresh_nonce(&self, ino: u32) -> [u8; crate::crypto::uapi::FILE_NONCE_SIZE] {
        let mut n = [0u8; crate::crypto::uapi::FILE_NONCE_SIZE];
        for (i, b) in n.iter_mut().enumerate() {
            *b = self.sb.uuid.get(i).copied().unwrap_or(0)
                ^ (ino.rotate_left(i as u32 * 5) as u8)
                ^ (self.cp.version as u8);
        }
        n
    }

    /// One kind of a verity file's metadata, from `offset`, at most `length`
    /// bytes.
    ///
    /// The tree and the descriptor live PAST the file's own length, where the
    /// ordinary reader will not go, so they are read through the map rather
    /// than through the file.
    /// # C: O(bytes)
    pub fn verity_metadata(&self, ino: u32, kind: u64, offset: u64, length: u64)
        -> Result<Vec<u8>, Errno> {
        use crate::verity;
        let inode = self.read_inode(ino)?;
        let attr = self.verity_attr(&inode, ino)?;
        let loc = verity::location::parse(&attr).map_err(|e| e.errno())?;
        let whole: Vec<u8> = match kind {
            super::uapi::VERITY_METADATA_TYPE_MERKLE_TREE => {
                let desc = self.read_past_end(&inode, ino, loc.pos, loc.size as usize)?;
                let d = verity::descriptor::parse(&desc).map_err(|e| e.errno())?;
                let size = verity::descriptor::tree_size(&d, inode.size)
                    .map_err(|e| e.errno())?;
                self.read_past_end(&inode, ino, verity::metadata_pos(inode.size),
                                   size as usize)?
            }
            super::uapi::VERITY_METADATA_TYPE_DESCRIPTOR =>
                self.read_past_end(&inode, ino, loc.pos, loc.size as usize)?,
            super::uapi::VERITY_METADATA_TYPE_SIGNATURE => {
                let desc = self.read_past_end(&inode, ino, loc.pos, loc.size as usize)?;
                let d = verity::descriptor::parse(&desc).map_err(|e| e.errno())?;
                verity::descriptor::signature(&desc, &d).map_err(|e| e.errno())?
            }
            _ => return Err(Errno::Einval),
        };
        // A start past the end is not an error: it is the caller having read
        // everything, and it answers with nothing.
        let from = (offset as usize).min(whole.len());
        let to = (from + length as usize).min(whole.len());
        Ok(whole[from..to].to_vec())
    }

    /// Discard the free space of the main area within `[start, start+len)`,
    /// reporting the bytes offered and the granularity actually used.
    ///
    /// The granularity is raised to the device's own when the caller asks for
    /// less, and reported back, because a caller that asked for single blocks
    /// and got whole segments needs to know which it got.
    /// # C: O(segments)
    pub fn trim_free_space(&mut self, start: u64, len: u64, minlen: u64)
        -> Result<(u64, u64), Errno> {
        let blk = crate::uapi::BLKSIZE as u64;
        let per_seg = u64::from(crate::uapi::BLKS_PER_SEG);
        let granularity = minlen.max(blk);
        let main = u64::from(self.sb.main_blkaddr) * blk;
        let end = start.saturating_add(len).min(
            main + u64::from(self.sb.segment_count_main) * per_seg * blk);
        if end <= start { return Ok((0, granularity)); }
        self.load_segments()?;
        let mut offered = 0u64;
        for segno in 0..self.sb.segment_count_main {
            let seg_at = main + u64::from(segno) * per_seg * blk;
            if seg_at + per_seg * blk <= start || seg_at >= end { continue; }
            if !self.seg_is_free(segno) || self.is_current(segno) { continue; }
            let span = per_seg * blk;
            if span < granularity { continue; }
            let first = self.sb.main_blkaddr + segno * crate::uapi::BLKS_PER_SEG;
            for b in 0..crate::uapi::BLKS_PER_SEG { self.note_discard(first + b); }
            offered += span;
        }
        Ok((offered, granularity))
    }
}

#[cfg(test)]
#[path = "../tests/ioctl/vol.rs"]
mod tests;
