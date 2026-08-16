// The mountable filesystem.
//
// The mount root is the node tree itself, so a path walk crosses into the
// mount and `statfs` reports the interface's own magic. A mount whose root
// were absent would be admitted and then be invisible to the post-mount
// verification userspace runs.

use alloc::sync::Weak;

use vfs::superblock::SuperBlock;
use vfs::{InodeRef, KResult};

/// `/sys/fs/selinux`.
pub struct SelinuxFs;

impl vfs::fs::FileSystem for SelinuxFs {
    /// # C: O(1)
    fn name(&self) -> &str { "selinuxfs" }

    /// # C: O(1)
    fn magic(&self) -> u64 { crate::SELINUX_MAGIC }

    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(crate::root::selinux_root().as_inode()) }

    /// # C: O(1)
    fn set_sb(&self, sb: Weak<SuperBlock>) -> KResult<()> {
        crate::root::selinux_root().set_sb(sb);
        Ok(())
    }
}
