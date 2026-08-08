// Per-mount-namespace deep clone of a pseudo-fs tree (`unshare(CLONE_NEWNS)`).
// Split out of `tree.rs` at the 500-line cutoff; this file owns the single
// question "what does a namespace copy share, and what does it duplicate".

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};

use sync::Spinlock;
use vfs::{FileType, InodeBuilder, InodeRef};

use super::{PseudoDir, PseudoEntry};

impl PseudoDir {
    /// Independent copy of a device-node leaf inode for a fresh mount namespace:
    /// same behaviour (i_op/i_fop/i_private/rdev — identical device + routing
    /// ino) but its OWN mutable owner/mode so per-namespace chmod/chown does not
    /// leak. # C: O(1)
    fn clone_device_leaf(leaf: &InodeRef) -> InodeRef {
        let inode = InodeBuilder::new(
            leaf.ino(),
            leaf.i_mode() as u32,
            Arc::clone(leaf.i_op()),
            Arc::clone(leaf.i_fop()),
        )
        .rdev(leaf.rdev())
        .fsid(leaf.fsid())
        .private(Arc::clone(leaf.i_private()))
        .build();
        let _ = inode.set_owner(leaf.uid().unwrap_or(0), leaf.gid().unwrap_or(0));
        // Preserve the public-device (perm-immutable) mark so a per-namespace
        // copy of /dev/null etc. keeps its universal-access invariant too.
        if leaf.is_public_device() { inode.mark_public_device(); }
        inode
    }

    /// Recursive namespace copy. The clone keeps the owning filesystem's
    /// `dir_iops` default, so a private `/dev` publishes the same inode-op
    /// surface — including `fileattr` — as the tree it was cloned from.
    /// # C: O(N nodes)
    pub fn deep_clone(&self) -> Arc<PseudoDir> {
        let g = self.children.lock();
        let mut nc: BTreeMap<String, PseudoEntry> = BTreeMap::new();
        for (k, v) in g.iter() {
            let nv = match v {
                PseudoEntry::Dir(d) => PseudoEntry::Dir(d.deep_clone()),
                // Device-node leaves carry per-namespace MUTABLE metadata
                // (i_uid/i_gid/i_mode a service's PrivateDevices chmod/chown
                // writes). Sharing the Arc across mount namespaces let one
                // service's `chown /dev/null` corrupt /dev/null for EVERY other
                // namespace (the greeter then hit EACCES → glib "Failed to open
                // file to remap file descriptor"). Give each namespace its own
                // copy; share the immutable behaviour (i_op/i_fop/i_private/rdev
                // → same device, same routing ino). Non-device leaves (dynamic
                // procfs/sysfs files + symlinks) carry no mutable per-ns state,
                // so they stay shared.
                PseudoEntry::Leaf(i) => PseudoEntry::Leaf(
                    if matches!(i.file_type(), FileType::CharDev | FileType::BlockDev) {
                        Self::clone_device_leaf(i)
                    } else {
                        Arc::clone(i)
                    },
                ),
            };
            nc.insert(k.clone(), nv);
        }
        Arc::new(PseudoDir {
            ino: self.ino,
            path: self.path.clone(),
            fsid: self.fsid,
            sb: Spinlock::new(self.sb.lock().clone()),
            children: Spinlock::new(nc),
            inode: Spinlock::new(Weak::new()),
            hooks: Spinlock::new(self.hooks.lock().clone()),
            dir_iops: Arc::clone(&self.dir_iops),
        })
    }
}
