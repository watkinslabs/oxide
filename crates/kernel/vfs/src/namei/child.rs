//! One component's child resolution: dcache fast path, `i_op->lookup` slow
//! path, negative-dentry caching (Linux `lookup_fast` / `lookup_slow`).
//!
//! Owned by one function because the walk consults it from two places — every
//! ordinary component, and the trailing component of a `LOOKUP_PARENT` walk that
//! an open asked to follow. A second copy for the trailing case would be a
//! second answer to "does this name exist", which is the split the walk exists
//! to prevent.

extern crate alloc;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::types::{KResult, VfsError};

use super::state::Nameidata;

/// What one component's resolution produced. `Missing` is a DEFINITIVE miss —
/// the name is not there — which the ordinary walk reports as `ENOENT` and a
/// create's trailing component treats as the name it is about to create.
pub(crate) enum ChildLookup {
    Found(Arc<Dentry>),
    Missing,
    /// rcu (lazy) walk hit a dcache miss: the blocking slow path may not run
    /// under an rcu read-side, so the walk restarts in ref mode.
    Restart,
}

impl Nameidata {
    /// Resolve `comp` within the current directory. # C: O(1) cached, O(dir-lookup) cold
    pub(crate) fn lookup_child(&mut self, comp: &str) -> KResult<ChildLookup> {
        // Fast path `d_lookup` (parent,name)-keyed. D5/D6: a confirmed MISS is
        // cached as a NEGATIVE dentry (so a repeated lookup/stat of the same name
        // is served from the dcache WITHOUT re-walking the blocking slow path),
        // but ONLY on a filesystem that is `neg_cache_ok` — one whose namespace
        // mutates exclusively through the flushed create/unlink/rename syscalls.
        // On a pseudo-fs the miss propagates un-cached (re-walks next time), so a
        // dynamically-appearing entry is never masked.
        match crate::dcache::d_lookup_reval(&self.cur_dentry, comp, self.flags.reval) {
            Some(d) if !d.is_negative() => return Ok(ChildLookup::Found(d)),
            Some(_) => return Ok(ChildLookup::Missing), // cached negative (definitive)
            // RESOLVE_CACHED: a dcache miss would take the (possibly blocking)
            // `i_op->lookup` slow path — refuse with EAGAIN instead (Linux
            // `LOOKUP_CACHED`).
            None if self.flags.cached => return Err(VfsError::Eagain),
            // rcu (lazy) walk: a dcache MISS must take the blocking
            // `i_op->lookup` slow path under `i_rwsem`, which an rcu read-side may
            // not hold — leave LOOKUP_RCU and restart the walk in ref mode (Linux
            // `lookup_slow` is reached only after `try_to_unlazy`).
            None if self.rcu => { self.rcu = false; return Ok(ChildLookup::Restart); }
            None => {}
        }
        // `lookup_slow` (Linux `fs/namei.c`): take the PARENT directory's
        // `i_rwsem` SHARED across the blocking `i_op->lookup` + dcache install, so
        // the (parent,name) resolution is consistent against a concurrent mutator
        // that holds the SAME `i_rwsem` EXCLUSIVE (create/unlink/rename, in the
        // syscall layer). DEADLOCK-FREE: a single shared acquire, no other
        // `i_rwsem` nested under it, dropped at the end of THIS component (RAII) —
        // never spanning two components — so no cycle is possible; the only
        // same-rank lock `d_add` takes is a DIFFERENT dentry's `d_inode` pointer
        // lock, always acquired after (never before) this one. Rank: `i_rwsem`
        // (40) is below the dcache Dentry (50)/Superblock (60) locks `d_add`
        // takes, so the chain is ascending.
        let _dir_lk = self.cur_inode.inode_lock_shared();
        match self.cur_inode.lookup(comp) {
            Ok(ci) => {
                // D3/D37: `lookup` returned `ci` carrying the iget/build hold;
                // `d_add` takes the dentry's OWN counted hold (`grab_inode_hold`).
                // Release the walk's temporary so `i_count` tracks (aliases + open
                // files) and can reach 0 for eviction (Linux `d_splice_alias`/
                // `d_add` consumes the caller's iget ref). iput AFTER the grab →
                // never evicts a live inode; on the race-loser path the dentry
                // already counts its inode, so this drops the redundant build.
                let child = crate::dcache::d_add(&self.cur_dentry, comp, ci.clone());
                crate::file::iput(ci);
                Ok(ChildLookup::Found(child))
            }
            Err(VfsError::Enoent) => {
                // D5/D6 negative-on-miss, gated for safety (see `neg_cache_ok`):
                // create syscalls flush this leaf negative by resolved parent
                // dentry/name, so a subsequently-created file is never masked.
                if super::neg_cache_ok(&self.cur_inode) {
                    crate::dcache::d_add_negative(&self.cur_dentry, comp);
                }
                Ok(ChildLookup::Missing)
            }
            Err(e) => Err(e),
        }
    }
}
