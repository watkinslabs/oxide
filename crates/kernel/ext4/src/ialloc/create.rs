extern crate alloc;

use alloc::vec;

use crate::dir;
use crate::gdt;
use crate::inode::{self, I_BLOCK_LEN, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK};
use crate::mount::{Mount, MountError};

use super::stamp_owner;

impl Mount {
    /// Create a regular file `name` under directory `parent_ino`.
    /// Allocates an inode, writes a fresh on-disk inode (mode
    /// `S_IFREG | mode_perm`, nlink=1, empty extent tree, size 0),
    /// and adds a directory entry. Returns the new inode number.
    /// `uid`/`gid` are the fs-domain owner ids stamped on the new inode
    /// (Linux `ext4_new_inode`).
    /// # C: O(N parent entries) + 1 inode-alloc + 2 block I/Os
    pub fn create_file(
        &self,
        parent_ino: u32,
        name: &[u8],
        mode_perm: u16,
        uid: u32,
        gid: u32,
    ) -> Result<u32, MountError> {
        self.run_journaled(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            m.init_inode(new_ino, S_IFREG | (mode_perm & 0x0FFF), 1, uid, gid)?;
            m.dir_link(parent_ino, name, new_ino, dir::DT_REG)?;
            Ok(new_ino)
        })
    }

    /// Create an empty subdirectory `name` under `parent_ino`.
    /// Allocates a fresh inode, initializes mode `S_IFDIR | perm`,
    /// nlink=2 (the implicit `.` self-link), then `dir_link`s the
    /// name into the parent. The new directory has no `.` / `..`
    /// data block yet — callers that need to populate it should
    /// follow with `append_block`.
    /// # C: O(parent entries) + 1 inode alloc + 2 I/Os
    pub fn create_dir(
        &self,
        parent_ino: u32,
        name: &[u8],
        mode_perm: u16,
        uid: u32,
        gid: u32,
    ) -> Result<u32, MountError> {
        self.run_journaled(|m| {
            let bs = m.sb.block_size as usize;
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            m.init_inode(new_ino, S_IFDIR | (mode_perm & 0x0FFF), 2, uid, gid)?;
            let usable = crate::csum::dir_usable_len(&m.sb, bs);
            let mut blk = alloc::vec![0u8; bs];
            blk[0..4].copy_from_slice(&new_ino.to_le_bytes());
            blk[4..6].copy_from_slice(&12u16.to_le_bytes());
            blk[6] = 1;
            blk[7] = dir::DT_DIR;
            blk[8] = b'.';
            blk[12..16].copy_from_slice(&parent_ino.to_le_bytes());
            blk[16..18].copy_from_slice(&((usable - 12) as u16).to_le_bytes());
            blk[18] = 2;
            blk[19] = dir::DT_DIR;
            blk[20] = b'.';
            blk[21] = b'.';
            let (_pf, ngen) = m.inode_flags_gen(new_ino)?;
            crate::csum::stamp_dirent_tail(&m.sb, new_ino, ngen, &mut blk);
            m.append_block(new_ino, &blk)?;
            m.set_inode_size(new_ino, bs as u64)?;
            m.dir_link(parent_ino, name, new_ino, dir::DT_DIR)?;
            let ng = (new_ino - 1) / m.sb.inodes_per_group;
            {
                let mut s = m.state.lock();
                gdt::adjust_used_dirs(&mut s.gdt_buf, ng, &m.sb, 1)?;
            }
            m.persist_gdt_slot_meta(ng)?;
            let (mut pb, _poff) = m.read_inode_bytes(parent_ino)?;
            let pl = u16::from_le_bytes([pb[0x1A], pb[0x1B]]).saturating_add(1);
            pb[0x1A..0x1C].copy_from_slice(&pl.to_le_bytes());
            m.write_inode_bytes(parent_ino, &pb)?;
            Ok(new_ino)
        })
    }

    /// Create a symlink `name` under `parent_ino` whose target is
    /// `target`. Fast-symlink path (target <= 60 B) writes target
    /// directly into `i_block`; slow path allocates one data block.
    /// `target` must be non-empty and <= one filesystem block.
    /// # C: O(N parent entries) + 1 inode-alloc + (target>60 ? 1 block-alloc + 2 block I/Os : 1 inode I/O)
    pub fn create_symlink(
        &self,
        parent_ino: u32,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<u32, MountError> {
        let bs = self.sb.block_size as usize;
        if target.is_empty() || target.len() > bs {
            return Err(MountError::Inode(inode::InodeError::BadLen));
        }
        self.run_journaled(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            m.init_inode(new_ino, S_IFLNK | 0o777, 1, uid, gid)?;
            if target.len() <= I_BLOCK_LEN {
                let (mut bytes, _off) = m.read_inode_bytes(new_ino)?;
                for b in &mut bytes[0x28..0x28 + I_BLOCK_LEN] {
                    *b = 0;
                }
                bytes[0x28..0x28 + target.len()].copy_from_slice(target);
                let n = target.len() as u64;
                bytes[0x04..0x08].copy_from_slice(&((n & 0xFFFF_FFFF) as u32).to_le_bytes());
                bytes[0x6C..0x70].copy_from_slice(&((n >> 32) as u32).to_le_bytes());
                m.write_inode_bytes(new_ino, &bytes)?;
            } else {
                let (mut b, _o) = m.read_inode_bytes(new_ino)?;
                let fl = u32::from_le_bytes([b[0x20], b[0x21], b[0x22], b[0x23]]) | 0x0008_0000;
                b[0x20..0x24].copy_from_slice(&fl.to_le_bytes());
                m.write_inode_bytes(new_ino, &b)?;
                let mut buf = vec![0u8; bs];
                buf[..target.len()].copy_from_slice(target);
                m.append_block(new_ino, &buf)?;
                m.set_inode_size(new_ino, target.len() as u64)?;
            }
            m.dir_link(parent_ino, name, new_ino, dir::DT_LNK)?;
            Ok(new_ino)
        })
    }

    /// Create a device/FIFO/socket node `name` under `parent_ino`.
    /// `mode` must encode one of `S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK`
    /// in its file-type bits; `rdev` is stored verbatim in
    /// `i_block[0..4]` for CHR/BLK (Linux "small dev" layout) and
    /// ignored for FIFO/SOCK.
    /// # C: O(N parent entries) + 1 inode-alloc + 1 inode I/O
    pub fn create_mknod(
        &self,
        parent_ino: u32,
        name: &[u8],
        mode: u16,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Result<u32, MountError> {
        let ftype = mode & S_IFMT;
        let dirent_dt = match ftype {
            S_IFCHR => dir::DT_CHR,
            S_IFBLK => dir::DT_BLK,
            S_IFIFO => dir::DT_FIFO,
            S_IFSOCK => dir::DT_SOCK,
            _ => return Err(MountError::Inode(inode::InodeError::BadLen)),
        };
        self.run_journaled(|m| {
            let parent_group = (parent_ino - 1) / m.sb.inodes_per_group;
            let new_ino = m.alloc_inode(parent_group)?;
            let mut bytes = vec![0u8; m.sb.inode_size as usize];
            bytes[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
            bytes[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
            stamp_owner(&mut bytes, uid, gid);
            if m.sb.inode_size as usize > crate::csum::EXT4_GOOD_OLD_INODE_SIZE {
                bytes[0x80..0x82].copy_from_slice(&32u16.to_le_bytes());
            }
            if matches!(ftype, S_IFCHR | S_IFBLK) {
                bytes[0x28..0x2C].copy_from_slice(&rdev.to_le_bytes());
            }
            m.write_inode_bytes(new_ino, &bytes)?;
            m.dir_link(parent_ino, name, new_ino, dirent_dt)?;
            Ok(new_ino)
        })
    }
}
