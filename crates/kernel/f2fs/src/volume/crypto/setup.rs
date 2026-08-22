//! Resolving an encrypted inode's key ONCE, at the operation that enters the
//! file, and handing the resolved record to everything below.
//!
//! Resolving a key is not cheap and it is not local: the policy is an attribute
//! on the inode, so it costs an attribute-area read, which costs a node read,
//! which takes a page lock that can BLOCK. Doing that at the point of use put
//! all of it underneath every partial block write in the filesystem — a write
//! already holding the state it is writing.
//!
//! The reference does none of it. Its key setup runs at the open (and at the
//! readdir, the lookup and the size change), and its contents en/decryption
//! then reads the inode's key with a RAW dereference guarded by a warning,
//! whose comment says in so many words that it may do so *because* the open
//! already did it. Its write path structurally cannot fetch a key: it asserts
//! one is present. `crypt_info_held` is that assertion, reporting `ENOKEY`
//! where the reference would warn and take the pointer.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::crypto::policy::Context;
use crate::crypto::{self, Info};
use crate::node::Inode;
use crate::uapi::XATTR_INDEX_ENCRYPTION;

use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// A nonce for a newly encrypted inode.
    ///
    /// Derived from the volume's own identity and the inode number rather
    /// than from a generator this crate does not have, so two inodes on one
    /// volume never share one and two volumes never produce the same pair.
    /// # C: O(1)
    pub(crate) fn fresh_nonce(&self, ino: u32) -> [u8; crypto::uapi::FILE_NONCE_SIZE] {
        let mut n = [0u8; crypto::uapi::FILE_NONCE_SIZE];
        for (i, b) in n.iter_mut().enumerate() {
            *b = self.sb.uuid.get(i).copied().unwrap_or(0)
                ^ (ino.rotate_left(i as u32 * 5) as u8)
                ^ (self.cp.version as u8);
        }
        n
    }

    /// Persist the context prepared for a new child, before its directory
    /// entry makes the inode reachable. This is the filesystem half of
    /// `fscrypt_set_context`: the policy decision stays in `crypto::inherit`,
    /// while this owner knows how the indexed attribute and inode flag reach
    /// the medium. # C: O(region bytes)
    pub(crate) fn crypt_store_new_context(&mut self, ino: u32, ctx: &Context)
        -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        let (bytes, used) = crate::crypto::policy::serialize(ctx);
        let area = self.xattr_area(&inode, ino)?;
        let mut attrs = crate::xattr::list(&area).map_err(|_| Errno::Eio)?;
        attrs.push(crate::xattr::Attr {
            index: XATTR_INDEX_ENCRYPTION,
            name: crypto::uapi::XATTR_NAME.to_vec(),
            value: bytes[..used].to_vec(),
        });
        self.store_xattrs(ino, &attrs)?;
        self.stamp_inode(ino, |b| {
            let at = crate::uapi::I_FLAGS;
            let held = u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
            crate::volume::dnode::put32(b, at, held | crate::flags::F2FS_ENCRYPT_FL);
        })
    }

    /// The context an encrypted inode stores, or `None` if it is not
    /// encrypted.
    ///
    /// Reached only from the resolution below and from the policy ioctls, which
    /// are about the context itself. Nothing on a read or write path may call
    /// it: that is the defect this file exists to prevent.
    /// # C: O(region bytes)
    pub(crate) fn crypt_context(&self, inode: &Inode, ino: u32)
        -> Result<Option<Context>, Errno> {
        if !inode.encrypted() { return Ok(None); }
        let area = self.xattr_area(inode, ino)?;
        let raw: Vec<u8> =
            crate::xattr::get(&area, XATTR_INDEX_ENCRYPTION, crypto::uapi::XATTR_NAME)
                .map_err(|_| Errno::Eio)?
                .ok_or(Errno::Enodata)?;
        crypto::policy::parse(&raw).map(Some).map_err(|e| e.errno())
    }

    /// Read the medium and build this inode's key, caching it.
    ///
    /// `Ok(None)` covers BOTH an unencrypted inode and an encrypted one whose
    /// key is absent; the callers below separate the two by the inode's own
    /// flag, so this one place never has to decide which of them a given caller
    /// can proceed without.
    /// # C: O(region bytes) once per inode
    #[inline(never)]
    fn crypt_resolve(&self, inode: &Inode, ino: u32) -> Result<Option<Arc<Info>>, Errno> {
        let Some(ctx) = self.crypt_context(inode, ino)? else { return Ok(None) };
        let Some(mk) = self.fscrypt_keys.get(&ctx.policy.key) else { return Ok(None) };
        let facts = self.crypt_inode_facts(inode);
        let fs = self.crypt_fs_facts(inode);
        let info = Info::setup_inline(&ctx, &facts, &fs, mk, &self.sb.uuid, ino,
                                      &self.inline_crypto()).map_err(|e| e.errno())?;
        let held = Arc::new(info);
        self.crypt_cache.borrow_mut().insert(ino, held.clone());
        Ok(Some(held))
    }

    /// Establish this inode's key if it is not established already, WITHOUT
    /// requiring one to be available.
    ///
    /// What a listing and a lookup need: a locked directory still lists its
    /// entries as the encoded records a later lookup decodes back, so an absent
    /// key is an answer rather than a failure. Idempotent, and free once the
    /// record is in hand.
    /// # C: O(1) once resolved, O(region bytes) on the first touch
    pub(crate) fn crypt_setup_info(&self, inode: &Inode, ino: u32)
        -> Result<Option<Arc<Info>>, Errno> {
        if let Some(held) = self.crypt_cache.borrow().get(&ino).cloned() { return Ok(Some(held)); }
        self.crypt_resolve(inode, ino)
    }

    /// The same, requiring the key to be there.
    ///
    /// What every operation that has to produce or consume this inode's
    /// PLAINTEXT does first — a read, a write, a truncation, a name being
    /// created. An encrypted inode whose key is absent is refused here, at the
    /// entry, so a caller hears `ENOKEY` before anything is changed rather than
    /// part way through.
    /// # C: O(1) once resolved, O(region bytes) on the first touch
    pub(crate) fn crypt_require_key(&self, inode: &Inode, ino: u32)
        -> Result<Option<Arc<Info>>, Errno> {
        let held = self.crypt_setup_info(inode, ino)?;
        if inode.encrypted() && held.is_none() { return Err(Errno::Enokey); }
        Ok(held)
    }

    /// What opening a file of this filesystem owes an encrypted inode.
    ///
    /// An encrypted file may be opened only with its key: there is no interface
    /// that serves the raw ciphertext, so a handle without the key is a handle
    /// that can do nothing with the bytes. Refusing at the open is what puts
    /// the key resolution on the one path that runs once per file, instead of
    /// on every block.
    /// # C: O(region bytes) once per inode
    pub(crate) fn crypt_file_open(&self, inode: &Inode, ino: u32) -> Result<(), Errno> {
        self.crypt_require_key(inode, ino).map(|_| ())
    }

    /// The record an earlier entry point resolved, WITHOUT going to the medium.
    ///
    /// The one accessor a read or write path may use. `Ok(None)` means the
    /// inode is not encrypted and there is nothing to apply; `ENOKEY` means it
    /// is encrypted and nobody resolved its key, which is a caller reaching
    /// these bytes without passing an entry point — the reference's warning
    /// case, reported instead of dereferenced.
    /// # C: O(log resolved inodes)
    pub(crate) fn crypt_info_held(&self, inode: &Inode, ino: u32)
        -> Result<Option<Arc<Info>>, Errno> {
        if !inode.encrypted() { return Ok(None); }
        self.crypt_cache.borrow().get(&ino).cloned().ok_or(Errno::Enokey).map(Some)
    }

    /// Whether a record is in hand for `ino`, for a test asking whether an
    /// operation's entry point resolved one. # C: O(log resolved inodes)
    #[cfg(test)]
    pub(crate) fn crypt_is_held(&self, ino: u32) -> bool {
        self.crypt_cache.borrow().contains_key(&ino)
    }

    /// Drop what is held for one inode, because the file behind the number has
    /// changed: it was freed, or it has just been given a policy.
    /// # C: O(log resolved inodes)
    pub(crate) fn crypt_forget(&self, ino: u32) { self.crypt_cache.borrow_mut().remove(&ino); }

    /// Drop everything, because the key table changed underneath it.
    /// # C: O(resolved inodes)
    pub(crate) fn crypt_forget_all(&self) { self.crypt_cache.borrow_mut().clear(); }
}
