//! debugfs's typed mount context.
//!
//! debugfs is the one filesystem here whose parse SWALLOWS a key it does not
//! know: the reference turns the "no such parameter" answer into success and
//! completes the mount. A table alone cannot express that — the generic
//! admission refuses an unlisted key, which is right for every other type — so
//! debugfs owns its parse the way the reference does, and the leniency is a
//! property of this one filesystem rather than a hole in the parser.
//!
//! `uid=`/`gid=`/`mode=` are still consumed and still land on the debugfs tree
//! root; a declared key given a bad value still fails the mount. Only an
//! unrecognised key is dropped.

extern crate alloc;

use alloc::sync::Arc;

use sync::{Spinlock, TaskList as LockClass};
use vfs::fs::{FsContext, FsContextOps, FsParameter, ParamResult};
use vfs::{SuperBlock, VfsError};

use kernfs::mount_opts::RootAttrOpts;

use crate::mount_opts::{debugfs_param, debugfs_superblock, stamp_debugfs};

/// Stateless operations object; the per-mount answer lives in `fc.fs_private`.
pub struct DebugfsContextOps;

fn state(fc: &mut FsContext) -> &Spinlock<RootAttrOpts, LockClass> {
    if fc.fs_private().downcast_ref::<Spinlock<RootAttrOpts, LockClass>>().is_none() {
        fc.set_fs_private(Arc::new(Spinlock::<RootAttrOpts, LockClass>::new(RootAttrOpts::default())));
    }
    fc.fs_private().downcast_ref::<Spinlock<RootAttrOpts, LockClass>>()
        .expect("debugfs fs_context private state")
}

impl FsContextOps for DebugfsContextOps {
    /// # C: O(len value)
    fn parse_param(&self, fc: &mut FsContext, param: &FsParameter)
        -> Result<ParamResult, VfsError>
    {
        // `source` is declared, and the reference's handler does no more than
        // record it — including refusing a second one. Declining hands it to
        // the VFS's own source rung, which is where that record lives.
        if param.key == "source" { return Ok(ParamResult::Declined); }
        let mut opts = *state(fc).lock();
        let known = match debugfs_param(&mut opts, param) {
            Ok(known) => known,
            Err(_) => return fc.invalf("debugfs: unexpected parameter value"),
        };
        // Unknown: consumed and dropped. Declining instead would send it to the
        // "unknown parameter" report and fail a mount the reference completes.
        if known { *state(fc).lock() = opts; }
        Ok(ParamResult::Consumed)
    }

    /// # C: O(1)
    fn get_tree(&self, fc: &mut FsContext) -> Result<Arc<SuperBlock>, VfsError> {
        let opts = *state(fc).lock();
        stamp_debugfs(&opts);
        debugfs_superblock(fc.fs_type().clone(), fc.sb_flags())
    }

    /// A remount re-applies only what this reconfigure named, so a field the
    /// caller left out keeps the value the live instance already has.
    /// # C: O(1)
    fn reconfigure(&self, fc: &mut FsContext) -> Result<(), VfsError> {
        let opts = *state(fc).lock();
        stamp_debugfs(&opts);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
