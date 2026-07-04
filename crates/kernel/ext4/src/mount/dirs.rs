use alloc::vec::Vec;

use crate::dir;
use crate::htree::EXT4_INDEX_FL;
use crate::inode::Inode;

use super::{Mount, MountError};

impl Mount {
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
        let mut newblk = alloc::vec![0u8; bs];
        newblk[0..4].copy_from_slice(&0u32.to_le_bytes());
        newblk[4..6].copy_from_slice(&(usable as u16).to_le_bytes());
        dir::insert(&mut newblk[..usable], child_ino, file_type, name)
            .map_err(MountError::Dir)?;
        crate::csum::stamp_dirent_tail(&self.sb, dir_ino, gen, &mut newblk);
        self.append_block(dir_ino, &newblk)?;
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
        for fb in 0..nblocks {
            let blk = self.read_file_block(dir_inode, fb)?;
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
        let mut cur_ino = 2u32;
        if path.is_empty() || path[0] != b'/' { return Err(MountError::NotFound); }
        let mut i = 1usize;
        while i < path.len() {
            while i < path.len() && path[i] == b'/' { i += 1; }
            if i >= path.len() { break; }
            let start = i;
            while i < path.len() && path[i] != b'/' { i += 1; }
            let comp = &path[start..i];
            let dir_node = self.read_inode(cur_ino)?;
            cur_ino = self.lookup_in_dir(&dir_node, comp)?;
        }
        Ok(cur_ino)
    }
}
