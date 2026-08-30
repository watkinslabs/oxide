//! Linux EA-inode value reader and persistent value metadata helpers.

use alloc::vec::Vec;

use crate::inode::flags::EXT4_EA_INODE_FL;
use crate::inode::{S_IFREG, S_IFMT};
use crate::mount::{Mount, MountError};

const I_VERSION_LO: usize = 0x24;
const I_CTIME: usize = 0x0C;
const I_ATIME: usize = 0x08;
const EA_REF_MAX: u64 = u64::MAX;
const EA_VALUE_MAX: usize = 64 * 1024;
const EA_DELETED_DTIME: u32 = 1_700_000_000;

impl Mount {
    /// Linux's fscrypt-independent EA-inode content hash. # C: O(value length)
    pub(crate) fn ea_value_hash(&self, value: &[u8]) -> u32 {
        crc::crc32c_update(self.sb.metadata_csum_seed(), value)
    }

    /// Allocate an unlinked regular inode and write one large xattr value into
    /// its extent data. The parent inode supplies Linux's allocation goal and
    /// owner ids; the EA inode itself remains hidden from directory lookup.
    /// # C: O(value length / block_size) + extent insertion
    pub(crate) fn create_ea_inode_in_transaction(&self, parent_ino: u32, value: &[u8])
        -> Result<u32, MountError>
    {
        if value.is_empty() || value.len() > EA_VALUE_MAX {
            return Err(MountError::NoSpace);
        }
        let parent = self.read_inode(parent_ino)?;
        let group = (parent_ino - 1) / self.sb.inodes_per_group;
        let ino = self.alloc_inode_in_transaction(group)?;
        let (_, mut raw) = self.init_inode_with_parent_bytes(
            &parent, ino, S_IFREG | 0o600, 1, parent.uid, parent.gid)?;
        let mut flags = u32::from_le_bytes(raw[0x20..0x24].try_into().unwrap());
        flags |= EXT4_EA_INODE_FL;
        raw[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        raw[I_ATIME..I_ATIME + 4].copy_from_slice(&self.ea_value_hash(value).to_le_bytes());
        Self::set_ea_inode_refcount(&mut raw, 1);
        self.write_inode_bytes(ino, &raw)?;

        let bs = self.sb.block_size as usize;
        let mut off = 0;
        while off < value.len() {
            let end = core::cmp::min(off + bs, value.len());
            let mut block = alloc::vec![0u8; bs];
            block[..end - off].copy_from_slice(&value[off..end]);
            self.append_block(ino, &block)?;
            off = end;
        }
        self.set_inode_size(ino, value.len() as u64)?;
        Ok(ino)
    }

    /// Find a byte-identical cached EA inode or create one and publish its
    /// reusable cache identity. Hash candidates are always re-read and
    /// compared, matching Linux mbcache collision handling. # C: O(N * value length)
    pub(crate) fn lookup_create_ea_inode(&self, parent_ino: u32, value: &[u8])
        -> Result<(u32, bool), MountError>
    {
        let hash = self.ea_value_hash(value);
        let candidates = self.state.lock().ea_inode_cache.get(&hash).cloned().unwrap_or_default();
        for ino in candidates {
            let Ok(node) = self.read_inode(ino) else { continue };
            if node.size != value.len() as u64 || node.i_flags & EXT4_EA_INODE_FL == 0 { continue; }
            let Ok(existing) = self.read_ea_inode_value(ino, value.len()) else { continue };
            if existing == value {
                self.inc_ea_inode_ref(ino)?;
                return Ok((ino, false));
            }
        }
        let ino = self.create_ea_inode_in_transaction(parent_ino, value)?;
        self.ea_inode_cache_insert(hash, ino);
        Ok((ino, true))
    }

    fn inc_ea_inode_ref(&self, ino: u32) -> Result<(), MountError> {
        let (mut raw, _) = self.read_inode_bytes(ino)?;
        let refs = Self::ea_inode_refcount(&raw);
        if refs == 0 || refs == EA_REF_MAX { return Err(MountError::BadBlock); }
        Self::set_ea_inode_refcount(&mut raw, refs + 1);
        self.write_inode_bytes(ino, &raw)
    }

    fn ea_inode_cache_insert(&self, hash: u32, ino: u32) {
        let mut state = self.state.lock();
        let list = state.ea_inode_cache.entry(hash).or_default();
        if !list.contains(&ino) { list.push(ino); }
    }

    fn ea_inode_cache_remove(&self, hash: u32, ino: u32) {
        let mut state = self.state.lock();
        if let Some(list) = state.ea_inode_cache.get_mut(&hash) {
            list.retain(|candidate| *candidate != ino);
            if list.is_empty() { state.ea_inode_cache.remove(&hash); }
        }
    }

    /// Drop one parent xattr reference. The final reference owns all extent
    /// blocks and the hidden inode slot, so both are reclaimed atomically.
    /// # C: O(extent tree) + O(1) inode teardown
    pub(crate) fn put_ea_inode(&self, ino: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let (mut raw, _) = m.read_inode_bytes(ino)?;
            let refs = Self::ea_inode_refcount(&raw);
            if refs == 0 { return Err(MountError::BadBlock); }
            if refs > 1 {
                Self::set_ea_inode_refcount(&mut raw, refs - 1);
                return m.write_inode_bytes(ino, &raw);
            }
            let hash = m.ea_inode_hash(&raw);
            m.truncate_inode_for_deletion(ino)?;
            let (mut dead, _) = m.read_inode_bytes(ino)?;
            dead[0x1A..0x1C].copy_from_slice(&0u16.to_le_bytes());
            dead[0x14..0x18].copy_from_slice(&EA_DELETED_DTIME.to_le_bytes());
            m.write_inode_bytes(ino, &dead)?;
            m.free_inode(ino)?;
            m.ea_inode_cache_remove(hash, ino);
            Ok(())
        })
    }

    /// Read and validate a Linux large-xattr inode value. The inode is hidden,
    /// extent-backed storage; holes, size mismatches, flags, and hash changes
    /// are corruption rather than an empty xattr. # C: O(extent depth + bytes)
    pub(crate) fn read_ea_inode_value(&self, ino: u32, size: usize)
        -> Result<Vec<u8>, MountError>
    {
        let node = self.read_inode(ino)?;
        if node.mode & S_IFMT != S_IFREG || node.i_flags & EXT4_EA_INODE_FL == 0
            || node.size != size as u64 {
            return Err(MountError::BadBlock);
        }
        if size == 0 { return Ok(Vec::new()); }
        let blocks = (size as u64).div_ceil(self.sb.block_size as u64);
        if blocks > u32::MAX as u64 { return Err(MountError::BadBlock); }
        let mut data = self.read_file_range(&node, 0, blocks as u32)?;
        data.truncate(size);
        let stored = self.ea_inode_hash(&self.read_inode_bytes(ino)?.0);
        let want = crc::crc32c_update(self.sb.metadata_csum_seed(), &data);
        if stored != want { return Err(MountError::BadChecksum); }
        self.ea_inode_cache_insert(stored, ino);
        Ok(data)
    }

    /// Hash used in the hidden inode's atime field and xattr entry hash.
    /// # C: O(value length)
    fn ea_inode_hash(&self, raw: &[u8]) -> u32 {
        u32::from_le_bytes([raw[I_ATIME], raw[I_ATIME + 1], raw[I_ATIME + 2], raw[I_ATIME + 3]])
    }

    /// Decode the persistent reference count carried by ctime/i_version.
    /// # C: O(1)
    pub(crate) fn ea_inode_refcount(raw: &[u8]) -> u64 {
        if raw.len() < I_VERSION_LO + 4 { return 0; }
        let lo = u32::from_le_bytes(raw[I_VERSION_LO..I_VERSION_LO + 4].try_into().unwrap()) as u64;
        let hi = if raw.len() >= I_CTIME + 4 {
            u32::from_le_bytes(raw[I_CTIME..I_CTIME + 4].try_into().unwrap()) as u64
        } else { 0 };
        (hi << 32) | lo
    }

    /// Encode a nonzero EA-inode reference count in the Linux raw inode.
    /// # C: O(1)
    pub(crate) fn set_ea_inode_refcount(raw: &mut [u8], refs: u64) {
        let refs = refs.min(EA_REF_MAX);
        raw[I_VERSION_LO..I_VERSION_LO + 4].copy_from_slice(&(refs as u32).to_le_bytes());
        raw[I_CTIME..I_CTIME + 4].copy_from_slice(&((refs >> 32) as u32).to_le_bytes());
    }
}
