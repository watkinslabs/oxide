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
    Found(Arc<Dentry>, crate::inode::InodeRef),
    Missing,
    /// rcu (lazy) walk hit a dcache miss: the blocking slow path may not run
    /// under an rcu read-side, so the walk restarts in ref mode.
    Restart,
}

impl Nameidata {
    /// Resolve `comp` within the current directory. # C: O(1) cached, O(dir-lookup) cold
    pub(crate) fn lookup_child(&mut self, comp: &str) -> KResult<ChildLookup> {
        #[cfg(feature = "debug-resolve-cost")]
        let _cost = crate::resolve_cost::child_lookup();
        // Fast path `d_lookup` (parent,name)-keyed. D5/D6: a confirmed MISS is
        // cached as a NEGATIVE dentry (so a repeated lookup/stat of the same name
        // is served from the dcache WITHOUT re-walking the blocking slow path),
        // but ONLY on a filesystem that is `neg_cache_ok` — one whose namespace
        // mutates exclusively through the flushed create/unlink/rename syscalls.
        // On a pseudo-fs the miss propagates un-cached (re-walks next time), so a
        // dynamically-appearing entry is never masked.
        // Linux computes qstr.hash while parsing the component and carries it
        // through both the fast probe and any slow dentry allocation.
        let hash = Dentry::compute_hash(Some(&self.cur_dentry), comp);
        let cached = {
            #[cfg(feature = "debug-resolve-cost")]
            let _probe_cost = crate::resolve_cost::dcache_probe();
            crate::dcache::d_lookup_reval_rcu_with_hash_and_inode(
                &self.cur_dentry,
                comp,
                self.flags.reval,
                self.rcu,
                hash,
            )
        };
        if let Some((d, inode)) = cached {
            if !d.d_is_positive() {
                // [NEG] a negative SERVED from cache: which parent identity
                // holds it. Alternating found/ENOENT for one path means two
                // parent identities each keeping their own child cache.
                #[cfg(feature = "debug-neg-trace")]
                if comp.contains("system_bus") {
                    klog::write_raw(b"[NEG serve parent=");
                    klog::write_hex_u64(alloc::sync::Arc::as_ptr(&self.cur_dentry) as u64);
                    klog::write_raw(b" ino=");
                    klog::write_hex_u64(self.cur_inode.ino());
                    klog::write_raw(b"]\n");
                }
                #[cfg(feature = "debug-resolve-cost")]
                crate::resolve_cost::dcache_negative();
                return Ok(ChildLookup::Missing);
            }
            if let Some(inode) = inode {
                #[cfg(feature = "debug-resolve-cost")]
                crate::resolve_cost::dcache_hit();
                return Ok(ChildLookup::Found(d, inode));
            }
            self.rcu = false;
            return Ok(ChildLookup::Restart);
        }
        // RESOLVE_CACHED: a dcache miss would take the (possibly blocking)
        // `i_op->lookup` slow path — refuse with EAGAIN instead (Linux
        // `LOOKUP_CACHED`).
        if self.flags.cached { return Err(VfsError::Eagain); }
        // rcu (lazy) walk: a dcache MISS must take the blocking
        // `i_op->lookup` slow path under an i_rwsem, so leave LOOKUP_RCU and
        // restart the walk in ref mode (Linux `try_to_unlazy`).
        if self.rcu { self.rcu = false; return Ok(ChildLookup::Restart); }
        #[cfg(feature = "debug-resolve-cost")]
        crate::resolve_cost::dcache_miss();
        // `lookup_slow`: take the PARENT directory's
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
        #[cfg(feature = "debug-resolve-cost")]
        let _slow_cost = crate::resolve_cost::slow_lookup();
        #[cfg(feature = "debug-resolve-cost")]
        let _parent_lock_cost = crate::resolve_cost::parent_lock();
        let _dir_lk = self.cur_inode.inode_lock_shared();
        #[cfg(feature = "debug-resolve-cost")]
        drop(_parent_lock_cost);
        #[cfg(feature = "debug-resolve-cost")]
        let _backend_cost = crate::resolve_cost::backend_lookup();
        let lookup = self.cur_inode.lookup(comp);
        let lookup = match lookup {
            Err(crate::types::VfsError::Enoent) if self.flags.case_insensitive => {
                match self.cur_inode.lookup_casefold(comp) {
                    Ok(inode) => Ok(inode),
                    Err(crate::types::VfsError::Enosys) => Err(crate::types::VfsError::Enoent),
                    Err(error) => Err(error),
                }
            }
            other => other,
        };
        match lookup {
            Ok(ci) => {
                #[cfg(feature = "debug-resolve-cost")]
                drop(_backend_cost);
                #[cfg(feature = "debug-resolve-cost")]
                let _install_cost = crate::resolve_cost::dentry_install();
                // D3/D37: `lookup` returned `ci` carrying the iget/build hold;
                // `d_add` takes the dentry's OWN counted hold (`grab_inode_hold`).
                // Release the walk's temporary so `i_count` tracks (aliases + open
                // files) and can reach 0 for eviction (Linux `d_splice_alias`/
                // `d_add` consumes the caller's iget ref). iput AFTER the grab →
                // never evicts a live inode; on the race-loser path the dentry
                // already counts its inode, so this drops the redundant build.
                let child_inode = ci.clone();
                let child = crate::dcache::d_add_with_hash(&self.cur_dentry, comp, ci.clone(), hash);
                crate::file::iput(ci);
                Ok(ChildLookup::Found(child, child_inode))
            }
            Err(VfsError::Enoent) => {
                // D5/D6 negative-on-miss, gated for safety (see `neg_cache_ok`):
                // create syscalls flush this leaf negative by resolved parent
                // dentry/name, so a subsequently-created file is not masked.
                //
                // The flush alone is not enough: it and this insert are not
                // ordered. A create landing between the backend miss above and
                // the insert below runs its flush FIRST, and the insert then
                // re-caches the stale negative, masking a file that exists --
                // measured as a bus-socket lookup answering ENOENT 25ms after
                // bind(2) created it, which left the resolver's bus reconnect
                // waiting forever. The reference cannot hit this because a
                // backend lookup and the negative's insertion happen under the
                // parent's lock that creation also takes; here the insert is
                // published first and the backend is asked AGAIN. Any create
                // that beat the insert is seen by the recheck; any create that
                // follows it must flush after it, which removes it.
                if super::neg_cache_ok(&self.cur_inode, comp) {
                    #[cfg(feature = "debug-neg-trace")]
                    if comp.contains("system_bus") {
                        klog::write_raw(b"[NEG insert parent=");
                        klog::write_hex_u64(alloc::sync::Arc::as_ptr(&self.cur_dentry) as u64);
                        klog::write_raw(b" ino=");
                        klog::write_hex_u64(self.cur_inode.ino());
                        klog::write_raw(b"]\n");
                    }
                    let negative = crate::dcache::d_add_negative_with_hash(&self.cur_dentry, comp, hash);
                    if let Ok(ci) = self.cur_inode.lookup(comp) {
                        crate::dcache::d_drop(&negative);
                        let child_inode = ci.clone();
                        let child = crate::dcache::d_add_with_hash(&self.cur_dentry, comp, ci.clone(), hash);
                        crate::file::iput(ci);
                        return Ok(ChildLookup::Found(child, child_inode));
                    }
                }
                Ok(ChildLookup::Missing)
            }
            Err(e) => Err(e),
        }
    }
}
