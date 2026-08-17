//! Bringing an identity's records in, and hanging them off the inode whose
//! allocations will be charged against them.
//!
//! Every quota-file read an allocation path does happens HERE, at an operation's
//! entry, and nowhere below it. That is the whole reason this is a separate file
//! from `charge`: the charging half is then a decision over memory, and can sit
//! underneath a node write without putting a file read there.

use alloc::vec::Vec;

use crate::quota::{self, Dqblk, Info};
use crate::uapi::{BLKSIZE, MAX_QUOTAS};
use crate::volume::map::Mapped;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::volume::Volume;

use super::{Owners, DEFAULT_PROJID};

impl<S: SectorSource> Volume<S> {
    /// Who an inode's allocations are charged to. # C: O(1 block)
    pub(crate) fn owners_of(&self, ino: u32) -> Result<Owners, Errno> {
        let i = self.read_inode(ino)?;
        Ok(Owners::new(i.uid, i.gid, i.projid))
    }

    /// Whether `ino` is one of the volume's own quota files. # C: O(kinds)
    pub(crate) fn is_quota_file(&self, ino: u32) -> bool {
        if quota::types::is_quota_inode(&self.sb.qf_ino, self.sb.feature, ino) { return true; }
        // A file the MOUNT named is as much a quota file as one the
        // superblock names, and the reason not to charge it is the same:
        // charging the growth of the file that records an identity's usage to
        // that identity does not terminate.
        ino != 0 && self.quota_setup.iter().any(|s| s.named && s.ino == ino)
    }

    /// Resolve every quota file the MOUNT named to the inode holding it.
    ///
    /// Those files are ordinary entries in the volume's root, so this cannot
    /// happen until there is a volume to look them up in. A name that does
    /// not resolve leaves its kind unaccounted rather than failing the mount:
    /// the reference logs and carries on, and a volume that refuses to mount
    /// over a missing quota file leaves nobody able to put one there.
    /// # C: O(kinds * depth)
    #[inline(never)]
    pub(crate) fn open_named_quota_files(&mut self) {
        for kind in 0..MAX_QUOTAS {
            if !self.quota_setup[kind].named { continue; }
            let Some(name) = &self.opts.jquota.names[kind] else {
                self.quota_setup[kind] = quota::Setup::OFF;
                continue;
            };
            let found = self
                .read_inode(self.sb.root_ino)
                .and_then(|root| self.lookup(&root, self.sb.root_ino, name.as_bytes()));
            match found {
                Ok(e) => self.quota_setup[kind].ino = e.ino,
                Err(_) => self.quota_setup[kind] = quota::Setup::OFF,
            }
        }
    }

    /// Acquire the records every allocation of this inode will be charged
    /// against, BEFORE the operation that allocates starts.
    ///
    /// This is the whole of the quota I/O an operation does. A quota file is an
    /// ordinary inode, so bringing a record in costs a file read — an index
    /// walk, a block fetch, and for a sealed file an attestation. Doing that
    /// from inside the charge would put all of it underneath a node write,
    /// where this filesystem is already holding the state it is writing; the
    /// reference acquires up front at each inode operation's entry for exactly
    /// that reason, and its charge then touches nothing but memory.
    ///
    /// Acquiring here is also what moves the failure to where a caller can act
    /// on it: a quota file that cannot be read fails the operation before it
    /// has changed anything, instead of half way through one.
    ///
    /// A kind whose record cannot be brought in because the kind was turned OFF
    /// underneath us is left unacquired rather than failed — the identity has
    /// nothing to be charged against, which is not the same as an error.
    /// # C: O(kinds * file bytes) on the first touch of an identity, O(kinds)
    /// after
    pub(crate) fn dquot_initialize(&mut self, ino: u32) -> Result<(), Errno> {
        if !self.quota_active() || self.is_quota_file(ino) { return Ok(()); }
        // Bringing an identity's records in is what "initialise the quotas of
        // this inode" means, so it is where a mount asking for that step to
        // fail gets its failure.
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::DquotInit) {
            return Err(Errno::Esrch);
        }
        let who = self.owners_of(ino)?;
        self.dquot_acquire(who)?;
        self.dquot_attach(ino, who);
        Ok(())
    }

    /// Hang a resolved identity off an inode, so the charges below can find it
    /// without going to the medium.
    ///
    /// Separate from the acquisition because the two happen at different
    /// moments for a file that does not exist yet: the identity is known from
    /// the request, the inode number only once one has been taken.
    /// # C: O(log live inodes)
    pub(crate) fn dquot_attach(&mut self, ino: u32, who: Owners) {
        self.dquot_owners.insert(ino, who);
    }

    /// Give a second inode the identities a first one already carries.
    ///
    /// A span's shadow inode is charged to the identity that owns the file it
    /// shadows, and it is made after that file was acquired, so it inherits
    /// rather than resolving again.
    /// # C: O(log live inodes)
    pub(crate) fn dquot_attach_like(&mut self, ino: u32, like: u32) {
        if let Some(who) = self.dquot_owners.get(&like).copied() {
            self.dquot_owners.insert(ino, who);
        }
    }

    /// Forget an inode's identities, because the number is about to belong to
    /// something else. # C: O(log live inodes)
    pub(crate) fn dquot_drop(&mut self, ino: u32) {
        self.dquot_owners.remove(&ino);
    }

    /// The identities `ino`'s allocations are charged against, as they were
    /// resolved when the operation started. # C: O(log live inodes)
    pub(super) fn dquot_owners_of(&self, ino: u32) -> Option<Owners> {
        self.dquot_owners.get(&ino).copied()
    }

    /// The same, for an inode that does not exist yet.
    ///
    /// A creation charges the identity the new file will belong to, and that
    /// identity is known from the request before the inode is written. Waiting
    /// for the inode would put the acquisition after the node write it is
    /// supposed to precede.
    /// # C: O(kinds * file bytes) once per identity
    pub(crate) fn dquot_initialize_new(&mut self, uid: u32, gid: u32) -> Result<(), Errno> {
        if !self.quota_active() { return Ok(()); }
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::DquotInit) {
            return Err(Errno::Esrch);
        }
        // A new inode carries the default project until something sets one.
        self.dquot_acquire(Owners::new(uid, gid, DEFAULT_PROJID))
    }

    /// Acquire for two inodes at once, for the operations that charge both.
    ///
    /// A rename charges the directory that gains the name and the one that
    /// loses it; a range exchange charges both files. Both records have to be
    /// held before either is touched, or the second half of the operation is
    /// the one that reads a quota file from under the write.
    /// # C: O(kinds * file bytes) once
    pub(crate) fn dquot_initialize_pair(&mut self, a: u32, b: u32) -> Result<(), Errno> {
        self.dquot_initialize(a)?;
        if b != a { self.dquot_initialize(b)?; }
        Ok(())
    }

    /// Bring in every accounted kind's header and record for one identity.
    /// # C: O(kinds * file bytes) once
    fn dquot_acquire(&mut self, who: Owners) -> Result<(), Errno> {
        for kind in 0..MAX_QUOTAS {
            if !quota::types::accounted(&self.quota_setup[kind]) { continue; }
            // The header comes off the same file and the same read as the
            // record, so acquiring the record is what makes the header held
            // too — nothing downstream has to go back for either.
            match self.dq_info(kind) {
                Ok(_) => {}
                // A kind turned off underneath us leaves the identity with
                // nothing to be charged against, which is not a failure of the
                // operation.
                Err(Errno::Esrch) => continue,
                Err(e) => return Err(e),
            }
            match self.dq_get(kind, who.id(kind)) {
                Ok(_) => {}
                Err(Errno::Esrch) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// The header this mount HOLDS for one kind, without going to the medium.
    ///
    /// `None` means no operation has acquired it, so nothing is charged against
    /// that kind — the charging path is not allowed to go and fetch it.
    /// # C: O(1)
    pub(super) fn dq_info_held(&self, kind: usize) -> Option<Info> { self.quota_info[kind].clone() }

    /// The record this mount HOLDS for one identity, without going to the
    /// medium. # C: O(log ids)
    pub(super) fn dq_held(&self, kind: usize, id: u32) -> Option<Dqblk> {
        self.dquots.get(&(kind, id)).cloned()
    }

    /// The parsed header of one kind's file. # C: O(file bytes) once
    pub(super) fn dq_info(&mut self, kind: usize) -> Result<Info, Errno> {
        if let Some(i) = self.quota_info[kind].clone() { return Ok(i); }
        let ino = self.quota_setup[kind].ino;
        if ino == 0 { return Err(Errno::Enodata); }
        let file = self.read_quota_file(ino)?;
        let info = quota::info::parse(&file, kind).map_err(|_| Errno::Eio)?;
        quota::info::check(&info, file.len()).map_err(|_| Errno::Eio)?;
        self.quota_info[kind] = Some(info.clone());
        Ok(info)
    }

    /// One kind's whole file, read through the quota inode's own mapping.
    ///
    /// NOT through the ordinary file reader, and the reference does not either:
    /// it gives the quota file a dedicated read that walks the inode's mapping
    /// and copies out of it. A quota file is the filesystem's own bookkeeping —
    /// it carries no seal, no encryption policy and no compressed cluster — so
    /// putting it through the reader that handles all three puts an
    /// attestation, and with it a hash-tree climb and a second index walk,
    /// statically underneath every checkpoint that flushes a record.
    ///
    /// A hole reads as zeroes, which is what a mapping read of a hole gives:
    /// the tree writes its blocks as it grows into them, and a region it has
    /// not reached yet holds nothing rather than being an error.
    /// # C: O(file bytes)
    pub(super) fn read_quota_file(&self, ino: u32) -> Result<Vec<u8>, Errno> {
        let inode = self.read_inode(ino)?;
        let len = inode.size as usize;
        let mut out = alloc::vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            let index = (done / BLKSIZE) as u64;
            let take = BLKSIZE.min(len - done);
            match self.map_block(&inode, ino, index)? {
                Mapped::At(addr) => {
                    let block = self.fill_data_page(ino, index, addr, None)?;
                    out[done..done + take].copy_from_slice(&block[..take]);
                }
                Mapped::Hole => {}
                // A quota file is never stored as clusters. One that reads as
                // compressed is not this filesystem's quota file.
                Mapped::Compressed => return Err(Errno::Eio),
            }
            done += take;
        }
        Ok(out)
    }

    /// The record for one identity, loaded once and then cached.
    ///
    /// An identity the tree has no slot for reads as an empty record rather
    /// than an error: it has simply never allocated anything, and refusing
    /// would make the first allocation by every new user fail.
    /// # C: O(file bytes) on the first touch, O(log ids) after
    pub(crate) fn dq_get(&mut self, kind: usize, id: u32) -> Result<Dqblk, Errno> {
        if let Some(d) = self.dquots.get(&(kind, id)) { return Ok(d.clone()); }
        let info = self.dq_info(kind)?;
        let file = self.read_quota_file(self.quota_setup[kind].ino)?;
        let d = quota::tree::read(&file, &info, id).map_err(|_| Errno::Eio)?.unwrap_or_default();
        self.dquots.insert((kind, id), d.clone());
        Ok(d)
    }
}
