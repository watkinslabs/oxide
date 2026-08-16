//! The mount's master keys, and an encrypted inode's key when it has one.
//!
//! A key is not on the volume. It is handed to the mount at runtime and lives
//! only in memory, so the same inode is readable or merely listable depending
//! on whether the key its context names has been added. Both states are
//! normal, and neither is an error: a locked directory still lists, and a
//! locked file still unlinks.
//!
//! The context, by contrast, IS on the volume — an attribute on every
//! encrypted inode, reached by INDEX rather than by a name a caller could
//! pass, the same way the verity location is. An inode flagged encrypted with
//! no context is damaged rather than merely locked, because nothing else
//! records which key and which modes its bytes were written under.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::crypto::policy::{Context, FsFacts, InodeFacts};
use crate::crypto::{self, Info, KeyId, MasterKey};
use crate::node::Inode;
use crate::uapi::{BLKSIZE, BLKSIZE_BITS, XATTR_INDEX_ENCRYPTION};

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Add a master key to this mount, reporting the name policies refer to
    /// it by.
    ///
    /// The name is derived FROM the key, so a caller cannot claim a name it
    /// does not hold the key for. # C: O(1)
    pub fn add_encryption_key(&mut self, raw: &[u8]) -> Result<KeyId, Errno> {
        let mk = MasterKey::new(raw).map_err(|e| e.errno())?;
        let id = KeyId::Identifier(mk.identifier());
        self.fscrypt_keys.insert(id, mk);
        Ok(id)
    }

    /// Add a master key under an arbitrary descriptor, which is how the older
    /// policy version names one. Nothing verifies the key matches the
    /// descriptor — that is the weakness the newer version exists to fix.
    /// # C: O(1)
    pub fn add_encryption_key_by_descriptor(&mut self, descriptor: [u8; 8], raw: &[u8])
        -> Result<KeyId, Errno> {
        let mk = MasterKey::new(raw).map_err(|e| e.errno())?;
        let id = KeyId::Descriptor(descriptor);
        self.fscrypt_keys.insert(id, mk);
        Ok(id)
    }

    /// Forget a key. Whether one was held. # C: O(log keys)
    pub fn remove_encryption_key(&mut self, id: &KeyId) -> bool {
        self.fscrypt_keys.remove(id).is_some()
    }

    /// What this volume can offer a policy.
    ///
    /// The file ceiling is the same arithmetic the index path uses, because it
    /// is what decides whether a data unit index fits beside an inode number
    /// in the policies that put both in one IV.
    /// # C: O(1)
    pub(crate) fn crypt_fs_facts(&self, inode: &Inode) -> FsFacts {
        FsFacts {
            max_file_bytes: crate::node::path::max_block(inode.addrs_per_inode())
                * BLKSIZE as u64,
            blkbits: BLKSIZE_BITS as u8,
        }
    }

    /// What the inode is, for the checks that depend on it. # C: O(1)
    pub(crate) fn crypt_inode_facts(&self, inode: &Inode) -> InodeFacts {
        let t = inode.mode & crate::mode::S_IFMT;
        InodeFacts {
            is_dir: t == crate::mode::S_IFDIR,
            is_reg: t == crate::mode::S_IFREG,
            is_symlink: t == crate::mode::S_IFLNK,
            casefolded: inode.casefolded(),
        }
    }

    /// The context an encrypted inode stores, or `None` if it is not
    /// encrypted. # C: O(region bytes)
    pub(crate) fn crypt_context(&self, inode: &Inode, ino: u32)
        -> Result<Option<Context>, Errno> {
        if !inode.encrypted() { return Ok(None); }
        let area = self.xattr_area(inode, ino)?;
        let raw: Vec<u8> =
            crate::xattr::get(&area, XATTR_INDEX_ENCRYPTION, crypto::uapi::XATTR_NAME)
                .map_err(|_| Errno::Eio)?
                .ok_or(Errno::Euclean)?;
        crypto::policy::parse(&raw).map(Some).map_err(|e| e.errno())
    }

    /// An encrypted inode's key, when this mount has been given it.
    ///
    /// `Ok(None)` covers BOTH an unencrypted inode and an encrypted one whose
    /// key is absent; a caller that cannot proceed without the key separates
    /// the two by the inode's own flag. Collapsing them here would make every
    /// caller decide, and one of them would decide wrong.
    /// # C: O(region bytes)
    pub(crate) fn crypt_info(&self, inode: &Inode, ino: u32) -> Result<Option<Info>, Errno> {
        let Some(ctx) = self.crypt_context(inode, ino)? else { return Ok(None) };
        let Some(mk) = self.fscrypt_keys.get(&ctx.policy.key) else { return Ok(None) };
        let facts = self.crypt_inode_facts(inode);
        let fs = self.crypt_fs_facts(inode);
        Info::setup(&ctx, &facts, &fs, mk, &self.sb.uuid, ino)
            .map(Some)
            .map_err(|e| e.errno())
    }
}
