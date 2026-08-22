use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{Ino, InodeRef};

use super::{PseudoDir, PseudoEntry};

impl PseudoDir {
    /// Resolve an inode number through this tree's canonical live nodes.
    /// Detached entries are absent because removal deletes them from the same
    /// child map this walk consults. # C: O(nodes)
    pub fn find_ino(self: &Arc<PseudoDir>, ino: Ino) -> Option<InodeRef> {
        if self.ino == ino { return Some(self.as_inode()); }
        let dirs = {
            let children = self.children.lock();
            for entry in children.values() {
                if let PseudoEntry::Leaf(inode) = entry {
                    if inode.ino() == ino { return Some(self.leaf_iget(inode)); }
                }
            }
            children.values().filter_map(|entry| match entry {
                PseudoEntry::Dir(dir) => Some(Arc::clone(dir)),
                PseudoEntry::Leaf(_) => None,
            }).collect::<Vec<_>>()
        };
        for dir in dirs {
            if let Some(inode) = dir.find_ino(ino) { return Some(inode); }
        }
        None
    }
}
