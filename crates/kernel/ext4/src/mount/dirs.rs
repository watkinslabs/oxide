use alloc::vec::Vec;

use crate::dir;
use crate::htree::EXT4_INDEX_FL;
use crate::inode::Inode;

use super::{Mount, MountError};

impl Mount {
    /// Grow directory `dir_ino` by one block, subject to the mount's
    /// `max_dir_size_kb=` ceiling.
    ///
    /// EVERY directory-growth path goes through here: linear overflow, htree
    /// conversion, and htree node and leaf splits. A ceiling only some of them
    /// consulted would be one a growing directory walks straight past by taking
    /// whichever path skipped it.
    ///
    /// `NoSpace` is the refusal, and it is the errno the reference returns from
    /// the same check: to the caller there is no room for the entry, which is
    /// exactly what the ceiling means.
    /// # C: O(N_extents) + 1 block I/O
    pub(crate) fn append_dir_block(&self, dir_ino: u32, data: &[u8]) -> Result<u32, MountError> {
        let b = self.behaviour();
        // Skip the inode read entirely on the mounts that set no ceiling, which
        // is every mount that did not name the option.
        if b.max_dir_size_kb != crate::mount_opts::behaviour::NO_DIR_SIZE_LIMIT {
            if !b.dir_may_grow(self.read_inode(dir_ino)?.size) { return Err(MountError::NoSpace); }
        }
        self.append_block(dir_ino, data)
    }

    /// Stamp the dir-block tail csum (no-op without metadata_csum)
    /// and write the block back through the journaled metadata path.
    /// # C: O(bs) csum + 1 block I/O
    fn write_dir_block(&self, dir_node: &Inode, dir_ino: u32, gen: u32, fb: u32, blk: &mut Vec<u8>)
        -> Result<(), MountError>
    {
        crate::csum::stamp_dirent_tail(&self.sb, dir_ino, gen, blk);
        self.run_journaled(|m| m.write_file_block_meta(dir_node, fb, blk))
    }

    /// Add a `name → child_ino` entry to directory `dir_ino`.
    ///
    /// Linear dirs: scan every data block for slack; insert into the
    /// first with room, reserving + restamping the metadata_csum tail.
    /// When all blocks are full, grow the directory by one fresh block.
    /// Indexed (htree) dirs: hash the name, descend the dx index to the
    /// covering leaf, and insert there (so Linux's hash lookup finds
    /// it). The dx index is never linear-overwritten — the prior code
    /// corrupted dx_root by splicing into block 0.
    /// # C: O(N entries) walk + O(1) block I/Os (+hash for htree)
    pub fn dir_link(&self, dir_ino: u32, name: &[u8], child_ino: u32, file_type: u8)
        -> Result<(), MountError>
    {
        self.run_journaled(|m| m.dir_link_inner(dir_ino, name, child_ino, file_type))
    }

    fn dir_link_inner(&self, dir_ino: u32, name: &[u8], child_ino: u32, file_type: u8)
        -> Result<(), MountError>
    {
        let dir_node = self.read_inode(dir_ino)?;
        if !dir_node.is_dir() { return Err(MountError::NotDir); }
        let (flags, gen) = self.inode_flags_gen(dir_ino)?;
        let bs = self.sb.block_size as usize;
        let usable = crate::csum::dir_usable_len(&self.sb, bs);

        if (flags & EXT4_INDEX_FL) != 0 {
            return self.htree_insert(&dir_node, dir_ino, gen, name, child_ino, file_type);
        }

        let total = dir_node.size;
        let nblocks = ((total + bs as u64 - 1) / bs as u64) as u32;
        for fb in 0..nblocks {
            let mut blk = self.read_file_block_meta(&dir_node, fb)?;
            if blk.len() < bs { blk.resize(bs, 0); }
            match dir::insert(&mut blk[..usable], child_ino, file_type, name) {
                Ok(()) => return self.write_dir_block(&dir_node, dir_ino, gen, fb, &mut blk),
                Err(dir::DirError::Full) => continue,
                Err(e) => return Err(MountError::Dir(e)),
            }
        }
        // Block 0 is full and dir_index is enabled → convert to an INDEXED
        // (htree) directory instead of appending a 2nd linear block (Linux
        // `make_indexed_dir` at the 1→2 block boundary; keeps lookup O(log N)).
        const COMPAT_DIR_INDEX: u32 = 0x0020;
        if nblocks == 1 && (self.sb.feature_compat & COMPAT_DIR_INDEX) != 0 {
            return self.htree_create(dir_ino, gen, name, child_ino, file_type);
        }
        let mut newblk = alloc::vec![0u8; bs];
        newblk[0..4].copy_from_slice(&0u32.to_le_bytes());
        newblk[4..6].copy_from_slice(&(usable as u16).to_le_bytes());
        dir::insert(&mut newblk[..usable], child_ino, file_type, name)
            .map_err(MountError::Dir)?;
        crate::csum::stamp_dirent_tail(&self.sb, dir_ino, gen, &mut newblk);
        self.append_dir_block(dir_ino, &newblk)?;
        Ok(())
    }

    /// Remove `name` from directory `dir_ino`. Returns the inode
    /// number of the unlinked target (caller decrements its link
    /// count + frees blocks/inode when nlink reaches 0). Scans every
    /// data block; restamps the metadata_csum tail of the modified
    /// block.
    /// # C: O(N entries) walk + 2 block I/Os
    pub fn dir_unlink(&self, dir_ino: u32, name: &[u8]) -> Result<u32, MountError> {
        self.run_journaled(|m| m.dir_unlink_inner(dir_ino, name))
    }

    fn dir_unlink_inner(&self, dir_ino: u32, name: &[u8]) -> Result<u32, MountError> {
        let dir_node = self.read_inode(dir_ino)?;
        if !dir_node.is_dir() { return Err(MountError::NotDir); }
        let (_flags, gen) = self.inode_flags_gen(dir_ino)?;
        let bs = self.sb.block_size as u64;
        let total = dir_node.size;
        let nblocks = ((total + bs - 1) / bs) as u32;
        for fb in 0..nblocks {
            let mut blk = self.read_file_block_meta(&dir_node, fb)?;
            match dir::remove(&mut blk, name) {
                Ok(removed) => {
                    self.write_dir_block(&dir_node, dir_ino, gen, fb, &mut blk)?;
                    return Ok(removed);
                }
                Err(dir::DirError::NotFound) => continue,
                Err(e) => return Err(MountError::Dir(e)),
            }
        }
        Err(MountError::NotFound)
    }

    /// Rewrite directory `dir_ino`'s `..` entry to point at `new_parent` — the
    /// on-disk half of a cross-parent directory move (Linux `ext4_rename`
    /// `ext4_rename_dir_finish`/`ext4_setent`). `..` lives in the first dir
    /// block; the dirent-tail metadata_csum is re-stamped by `write_dir_block`.
    /// Journaled. # C: O(entries in block 0) + 2 block I/Os
    pub fn set_dotdot(&self, dir_ino: u32, new_parent: u32) -> Result<(), MountError> {
        self.run_journaled(|m| m.set_dotdot_inner(dir_ino, new_parent))
    }

    fn set_dotdot_inner(&self, dir_ino: u32, new_parent: u32) -> Result<(), MountError> {
        let dir_node = self.read_inode(dir_ino)?;
        if !dir_node.is_dir() { return Err(MountError::NotDir); }
        let (_flags, gen) = self.inode_flags_gen(dir_ino)?;
        let bs = self.sb.block_size as usize;
        let mut blk = self.read_file_block_meta(&dir_node, 0)?;
        if blk.len() < bs { blk.resize(bs, 0); }
        let mut off = 0usize;
        loop {
            let (e, next) = match dir::next_entry(&blk, off) { Ok(v) => v, Err(_) => break };
            if e.inode != 0 && e.name == b".." {
                blk[off..off + 4].copy_from_slice(&new_parent.to_le_bytes());
                return self.write_dir_block(&dir_node, dir_ino, gen, 0, &mut blk);
            }
            if next <= off || next >= blk.len() { break; }
            off = next;
        }
        Err(MountError::NotFound)
    }

    /// Look `name` up in the directory. Walks all data blocks
    /// covered by the inode's `i_size`, not just the first —
    /// rootfs `/bin` overflows one 1 KiB block once we stage
    /// more than ~25 hardlinks alongside the coreutils binaries.
    /// # C: O(N_entries)
    pub fn lookup_in_dir(&self, dir_inode: &Inode, name: &[u8]) -> Result<u32, MountError> {
        if !dir_inode.is_dir() { return Err(MountError::NotDir); }
        let block_size = self.sb.block_size as u64;
        let total = dir_inode.size;
        let nblocks = ((total + block_size - 1) / block_size) as u32;
        // Linear dirs carry an `ext4_dir_entry_tail` metadata_csum on every
        // block (Linux ext4_dirblock_csum_verify → EFSBADCRC). htree dirs are
        // skipped here: their block 0 is a `dx_root` with a `dx_tail`, not a
        // dirent tail, so verifying it against the dirent seed would false-
        // reject. htree dx-block verify is a separate item. No-op w/o csum.
        let verify_tail = (dir_inode.i_flags & EXT4_INDEX_FL) == 0 && dir_inode.ino != 0;
        for fb in 0..nblocks {
            // Shadow-aware read (read-your-writes): under cross-op batching a dir
            // block just written by `dir_link` lives in `MountState.shadow` until
            // `commit_batch`. Reading via the plain `read_file_block` returned the
            // stale on-disk block, so a lookup of an entry created earlier in the
            // SAME batch missed it — Linux sees a transaction's own metadata
            // writes through the buffer cache; our shadow is that buffer.
            let blk = self.read_file_block_meta(dir_inode, fb)?;
            if verify_tail
                && !crate::csum::verify_dirent_tail(&self.sb, dir_inode.ino, dir_inode.generation, &blk)
            {
                return Err(MountError::BadChecksum);
            }
            match dir::lookup(&blk, name)? {
                Some(e) => return Ok(e.inode),
                None    => continue,
            }
        }
        Err(MountError::NotFound)
    }

    /// Walk an absolute path from the root inode (always 2 in ext4).
    /// Returns the final inode number.
    /// # C: O(path components × dir size)
    pub fn lookup_path(&self, path: &[u8]) -> Result<u32, MountError> {
        if path.is_empty() || path[0] != b'/' { return Err(MountError::NotFound); }
        self.lookup_path_from(2, path, 0)
    }

    /// Component walk with symlink following (Linux `link_path_walk`), starting
    /// at directory `start` (used for resolving a symlink target relative to the
    /// directory that held it). An absolute `path` restarts at the root (ino 2).
    /// Both intermediate directory symlinks (usrmerge `/lib`→`usr/lib`) and a
    /// final symlink (`/sbin/init`→`../lib/systemd/systemd`) are resolved, so a
    /// stock Fedora rootfs boots with no init-path hack. `depth` bounds symlink
    /// chains (ELOOP → NotFound). # C: O(components × symlink depth)
    fn lookup_path_from(&self, start: u32, path: &[u8], depth: u32) -> Result<u32, MountError> {
        const SYMLINK_MAX_DEPTH: u32 = 40;
        if depth > SYMLINK_MAX_DEPTH { return Err(MountError::NotFound); }
        let mut cur = if !path.is_empty() && path[0] == b'/' { 2u32 } else { start };
        let mut i = 0usize;
        while i < path.len() {
            while i < path.len() && path[i] == b'/' { i += 1; }
            if i >= path.len() { break; }
            let s = i;
            while i < path.len() && path[i] != b'/' { i += 1; }
            let comp = &path[s..i];
            let dir_node = self.read_inode(cur)?;
            let child = self.lookup_in_dir(&dir_node, comp)?;
            let child_node = self.read_inode(child)?;
            if child_node.is_link() {
                // Resolve the symlink target relative to the directory that held
                // it (`cur`), then continue the walk from the resolved inode.
                let target = self.read_symlink_target(child, &child_node)?;
                cur = self.lookup_path_from(cur, &target, depth + 1)?;
            } else {
                cur = child;
            }
        }
        Ok(cur)
    }

    /// Read a symlink's target bytes: fast (≤60B, inline in `i_block`) or slow
    /// (first data block, truncated to `i_size`). # C: O(1) or 1 block I/O
    fn read_symlink_target(&self, _ino: u32, inode: &Inode) -> Result<Vec<u8>, MountError> {
        if let Some(t) = inode.fast_symlink_target() { return Ok(t.to_vec()); }
        // Shadow-aware (read-your-writes): a slow symlink created earlier in the
        // same batch has its target block staged in the shadow, not yet on disk.
        let blk = self.read_file_block_meta(inode, 0)?;
        let n = (inode.size as usize).min(blk.len());
        Ok(blk[..n].to_vec())
    }
}
