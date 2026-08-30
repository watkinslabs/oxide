use alloc::string::String;
use alloc::vec::Vec;

use vfs::SimpleXattrs;

use crate::csum::EXT4_GOOD_OLD_INODE_SIZE;
use crate::mount::{Mount, MountError};

use super::{decode_ibody_with_mount, decode_entries, encode_ibody, BLOCK_HDR_LEN,
            DEFAULT_EXTRA_ISIZE, EXT4_GOOD_OLD_INODE_SIZE as XATTR_GOOD_OLD_INODE_SIZE};

impl Mount {
    /// Populate the in-core xattr store from the external block and ibody.
    /// The external block is read first; an ibody name wins on collision.
    /// # C: O(N entries + EA value bytes)
    pub fn load_xattrs(&self, ino: u32, store: &SimpleXattrs) {
        let isize = self.sb.inode_size as usize;
        let (bytes, _off) = match self.read_inode_bytes(ino) { Ok(x) => x, Err(_) => return };
        let facl = Self::file_acl_of(&bytes);
        if facl != 0 {
            if let Ok(blk) = self.read_metadata_block(facl) {
                self.xattr_cache_insert(facl, &blk);
                let mut entries = Vec::new();
                decode_entries(&blk, BLOCK_HDR_LEN, 0, blk.len(), Some(self), &mut entries);
                for (n, v) in entries { let _ = store.set(&n, v, false, false); }
            }
        }
        let extra = Self::extra_isize_of(&bytes, isize);
        if extra != 0 {
            for (n, v) in decode_ibody_with_mount(&bytes, XATTR_GOOD_OLD_INODE_SIZE + extra,
                                                   isize, Some(self)) {
                let _ = store.set(&n, v, false, false);
            }
        }
    }

    /// Encode the complete xattr set in the inode ibody and publish it.
    /// # C: O(N entries) + 1 journaled inode write
    pub fn store_ibody_xattrs(&self, ino: u32, entries: &[(String, Vec<u8>)])
        -> Result<(), MountError>
    {
        let isize = self.sb.inode_size as usize;
        if isize <= EXT4_GOOD_OLD_INODE_SIZE { return Err(MountError::NoSpace); }
        self.run_journaled(|m| {
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            let mut extra = Self::extra_isize_of(&bytes, isize);
            if extra == 0 {
                if EXT4_GOOD_OLD_INODE_SIZE + DEFAULT_EXTRA_ISIZE + 4 > isize {
                    return Err(MountError::NoSpace);
                }
                if !entries.is_empty() {
                    bytes[0x80..0x82].copy_from_slice(&(DEFAULT_EXTRA_ISIZE as u16).to_le_bytes());
                    extra = DEFAULT_EXTRA_ISIZE;
                } else { return Ok(()); }
            }
            let hdr_off = EXT4_GOOD_OLD_INODE_SIZE + extra;
            encode_ibody(&mut bytes, hdr_off, isize, entries).map_err(|_| MountError::NoSpace)?;
            m.write_inode_bytes(ino, &bytes)
        })
    }
}
