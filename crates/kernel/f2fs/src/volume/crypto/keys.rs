//! The master keys this mount has been given, and the facts an inode's key is
//! derived against.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::crypto::policy::{FsFacts, InodeFacts};
use crate::crypto::{self, KeyId, MasterKey};
use crate::node::Inode;
use crate::uapi::{BLKSIZE, BLKSIZE_BITS};

use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Add a master key to this mount, reporting the name policies refer to
    /// it by.
    ///
    /// The name is derived FROM the key, so a caller cannot claim a name it
    /// does not hold the key for. # C: O(resolved inodes)
    pub fn add_encryption_key(&mut self, raw: &[u8]) -> Result<KeyId, Errno> {
        let mk = MasterKey::new(raw).map_err(|e| e.errno())?;
        let id = KeyId::Identifier(mk.identifier());
        self.fscrypt_keys.insert(id, mk);
        self.crypt_forget_all();
        Ok(id)
    }

    /// Add a master key under an arbitrary descriptor, which is how the older
    /// policy version names one. Nothing verifies the key matches the
    /// descriptor — that is the weakness the newer version exists to fix.
    /// # C: O(resolved inodes)
    pub fn add_encryption_key_by_descriptor(&mut self, descriptor: [u8; 8], raw: &[u8])
        -> Result<KeyId, Errno> {
        let mk = MasterKey::new(raw).map_err(|e| e.errno())?;
        let id = KeyId::Descriptor(descriptor);
        self.fscrypt_keys.insert(id, mk);
        self.crypt_forget_all();
        Ok(id)
    }

    /// Forget a key. Whether one was held.
    ///
    /// Every record already resolved under it goes too, or a file opened while
    /// the key was present would keep being readable after it was taken away —
    /// the one thing removing a key is for. The buffered writes go out FIRST,
    /// because a page still waiting to be placed can only be encrypted by the
    /// key that is about to disappear, and the reference syncs the filesystem
    /// for exactly that reason before it evicts anything.
    /// # C: O(dirty pages + resolved inodes)
    pub fn remove_encryption_key(&mut self, id: &KeyId) -> bool {
        let _ = self.flush_all_data_pages();
        let held = self.fscrypt_keys.remove(id).is_some();
        self.crypt_forget_all();
        held
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

    /// What this mount will let the block layer do.
    ///
    /// Both halves come from outside the encryption code: whether the mount
    /// ASKED is a mount option, and what the device can do itself is the
    /// medium's business. Nothing here infers either, because turning inline
    /// encryption on by inference would change where a key lives on a mount
    /// that never requested it.
    /// # C: O(1)
    pub(crate) fn inline_crypto(&self) -> crypto::inline::Inline<'_> {
        crypto::inline::Inline {
            enabled: self.opts.inlinecrypt,
            profile: self.source.crypto_profile(),
        }
    }
}
