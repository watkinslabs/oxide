// The inode's cached POSIX ACLs (`inode->i_acl` / `inode->i_default_acl`) and
// the fetch that fills them (`get_inode_acl`).
//
// A permission check runs on every path component of every walk, and the ACL
// that decides it lives on the MEDIUM for every filesystem that stores one.
// Reading the attribute per check would put a volume lock and a block read in
// the middle of `path_lookup`, so the decoded entries are cached on the inode
// and the store is consulted once: the first check that needs them.
//
// Three states per slot, which is what the reference's two pointer sentinels
// encode: NOT CACHED (nothing has looked yet), cached as ABSENT (the object
// carries no ACL of this type — the common case, and the one that must cost
// nothing), and cached as PRESENT. The state word is read before the lock so an
// object with no ACL costs one atomic load per permission check.
//
// Invalidation is by GENERATION, not by clearing alone: a fetch that is in
// flight when the attribute is written must not install what it read over the
// newer value. The writer bumps the generation; a fetch stores only if the
// generation it started under still stands.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use sync::{Inode as InodeClass, Spinlock};

use crate::posix_acl::{AclEntry, AclType};
use crate::types::{KResult, VfsError};
use crate::xattr::XattrError;

use super::model::Inode;

/// Nothing has fetched this slot yet (`ACL_NOT_CACHED`).
const NOT_CACHED: u8 = 0;
/// Fetched, and the object carries no ACL of this type.
const CACHED_ABSENT: u8 = 1;
/// Fetched, and the entries are in the slot.
const CACHED_PRESENT: u8 = 2;

struct SlotInner { acl: Option<Arc<[AclEntry]>>, generation: u32 }

/// One cached ACL.
pub struct AclSlot {
    state: AtomicU8,
    inner: Spinlock<SlotInner, InodeClass>,
}

impl AclSlot {
    /// An empty, never-fetched slot. # C: O(1)
    pub fn new() -> Self {
        AclSlot { state: AtomicU8::new(NOT_CACHED),
                  inner: Spinlock::new(SlotInner { acl: None, generation: 0 }) }
    }

    /// `get_cached_acl` — the cached answer, or `None` when nothing has fetched
    /// this slot yet. The inner `None` is a cached ABSENCE. # C: O(1)
    pub fn cached(&self) -> Option<Option<Arc<[AclEntry]>>> {
        match self.state.load(Ordering::Acquire) {
            NOT_CACHED => None,
            CACHED_ABSENT => Some(None),
            _ => {
                let g = self.inner.lock();
                // Re-read under the lock: a writer between the two reads leaves
                // the state word describing entries the slot no longer holds.
                match self.state.load(Ordering::Relaxed) {
                    CACHED_PRESENT => Some(g.acl.clone()),
                    CACHED_ABSENT  => Some(None),
                    _ => None,
                }
            }
        }
    }

    /// The generation a fetch is about to run under. # C: O(1)
    fn generation(&self) -> u32 { self.inner.lock().generation }

    /// `set_cached_acl` for a fetch that started at `generation`. A write that
    /// landed in between wins, and this result is dropped. # C: O(1)
    fn fill(&self, acl: Option<Arc<[AclEntry]>>, generation: u32) {
        let mut g = self.inner.lock();
        if g.generation != generation { return; }
        let state = if acl.is_some() { CACHED_PRESENT } else { CACHED_ABSENT };
        g.acl = acl;
        self.state.store(state, Ordering::Release);
    }

    /// `forget_cached_acl` — the stored ACL changed, so what is here is wrong.
    /// # C: O(1)
    pub fn forget(&self) {
        let mut g = self.inner.lock();
        g.generation = g.generation.wrapping_add(1);
        g.acl = None;
        self.state.store(NOT_CACHED, Ordering::Release);
    }

    /// Install entries directly, for a caller that already knows them (a create
    /// that just wrote the inherited ACL). # C: O(1)
    pub fn set(&self, acl: Option<Arc<[AclEntry]>>) {
        let mut g = self.inner.lock();
        g.generation = g.generation.wrapping_add(1);
        let state = if acl.is_some() { CACHED_PRESENT } else { CACHED_ABSENT };
        g.acl = acl;
        self.state.store(state, Ordering::Release);
    }
}

impl Default for AclSlot {
    fn default() -> Self { Self::new() }
}

/// Both of an inode's cached ACLs.
pub struct AclCache { access: AclSlot, default: AclSlot }

impl AclCache {
    /// Two empty slots. # C: O(1)
    pub fn new() -> Self { AclCache { access: AclSlot::new(), default: AclSlot::new() } }

    fn slot(&self, ty: AclType) -> &AclSlot {
        match ty { AclType::Access => &self.access, AclType::Default => &self.default }
    }
}

impl Default for AclCache {
    fn default() -> Self { Self::new() }
}

impl Inode {
    /// `get_inode_acl` — this inode's POSIX ACL of `ty`, from the cache when it
    /// is there and from `i_op->get_inode_acl` when it is not. `None` is Linux's
    /// `NULL` ACL: the object carries none, and the mode bits decide.
    ///
    /// An error from the fetch is NOT cached: a transient read failure must not
    /// pin an object's permissions for the life of the inode. # C: O(1) cached
    pub fn get_inode_acl(&self, ty: AclType) -> KResult<Option<Arc<[AclEntry]>>> {
        let slot = self.i_acl.slot(ty);
        if let Some(hit) = slot.cached() { return Ok(hit); }
        let generation = slot.generation();
        let fetched: Option<Vec<AclEntry>> = self.i_op.get_inode_acl(self, ty)?;
        let acl: Option<Arc<[AclEntry]>> = fetched.map(|v| Arc::from(v.into_boxed_slice()));
        slot.fill(acl.clone(), generation);
        Ok(acl)
    }

    /// `forget_cached_acl` — drop what is cached for `ty`. # C: O(1)
    pub fn forget_cached_acl(&self, ty: AclType) { self.i_acl.slot(ty).forget(); }

    /// `forget_all_cached_acls`. # C: O(1)
    pub fn forget_all_cached_acls(&self) {
        self.forget_cached_acl(AclType::Access);
        self.forget_cached_acl(AclType::Default);
    }

    /// `set_cached_acl` — record entries the caller has just stored. # C: O(1)
    pub fn set_cached_acl(&self, ty: AclType, acl: Option<Arc<[AclEntry]>>) {
        self.i_acl.slot(ty).set(acl);
    }

    /// `posix_acl_chmod` — rewrite this inode's ACCESS ACL so it says what
    /// `mode` says, and hand the new entries back for the caller to store.
    /// `Ok(None)` when there is no ACL to rewrite, which is every object that
    /// carries only mode bits.
    ///
    /// Without this a `chmod` would change the mode bits and leave the ACL
    /// granting exactly what it granted before, so the tightening the caller
    /// asked for would not happen. # C: O(N_entries)
    pub fn posix_acl_chmod(&self, mode: u16) -> KResult<Option<Vec<AclEntry>>> {
        let Some(acl) = self.get_inode_acl(AclType::Access)? else { return Ok(None); };
        let mut entries = acl.to_vec();
        crate::posix_acl::chmod_masq(&mut entries, mode).map_err(|_| VfsError::Eio)?;
        Ok(Some(entries))
    }

    /// `posix_acl_chmod` through the filesystem's actual ACL store. The mode
    /// has already been applied by `->setattr`; this rewrites the access ACL to
    /// match it, removes a now-redundant ACL, and publishes the exact cached
    /// answer only after the backend write succeeds. # C: O(N_entries) + one
    /// attribute write
    pub fn store_posix_acl_chmod(&self, mode: u16) -> KResult<()> {
        let Some(entries) = self.posix_acl_chmod(mode)? else { return Ok(()); };
        let mut folded = mode;
        let keep = crate::posix_acl::equiv_mode(&entries, &mut folded)
            .map_err(|_| VfsError::Eio)?;
        let stored = if keep {
            self.setxattr(AclType::Access.xattr_name(), crate::posix_acl::to_xattr(&entries),
                          false, false)
        } else {
            self.removexattr(AclType::Access.xattr_name())
        };
        match stored {
            Ok(()) => {}
            Err(XattrError::NotFound) if !keep => {}
            Err(XattrError::NotFound) => return Err(VfsError::Enoent),
            Err(XattrError::Exists) => return Err(VfsError::Eexist),
            Err(XattrError::NotSup) => return Err(VfsError::Eopnotsupp),
            Err(XattrError::Fs(e)) => return Err(e),
        }
        let cached = if keep { Some(Arc::from(entries.into_boxed_slice())) } else { None };
        self.set_cached_acl(AclType::Access, cached);
        Ok(())
    }
}
