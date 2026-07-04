use alloc::sync::{Arc, Weak};

use vfs::superblock::SuperBlock;
use vfs::{Ino, InodeRef};

use crate::tree::PseudoDir;

pub struct PseudoFs {
    name: &'static str,
    magic: u64,
    root: Arc<PseudoDir>,
}

pub const PSEUDO_ROOT_INO: Ino = 1;

impl PseudoFs {
    pub fn new(name: &'static str, magic: u64) -> Arc<Self> {
        let root = PseudoDir::new_root(PSEUDO_ROOT_INO, magic);
        Arc::new(Self { name, magic, root })
    }

    pub fn root_dir(&self) -> &Arc<PseudoDir> {
        &self.root
    }
}

impl vfs::fs::FileSystem for PseudoFs {
    fn name(&self) -> &str {
        self.name
    }

    fn magic(&self) -> u64 {
        self.magic
    }

    fn root(&self) -> Option<InodeRef> {
        Some(self.root.as_inode())
    }

    fn set_sb(&self, sb: Weak<SuperBlock>) {
        self.root.set_sb(sb);
    }
}
