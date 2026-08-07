use alloc::sync::Arc;

use crate::superblock::{FileSystemType, SimpleSuperOps, SuperBlock};
use crate::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, KResult};

struct PseudoType;
impl FileSystemType for PseudoType {
    fn name(&self) -> &str { "pseudo-test" }
    fn mount(&self, _source: Option<&str>, _options: &str) -> KResult<Arc<SuperBlock>> {
        unreachable!("test constructs superblocks directly")
    }
}

fn superblock(dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(
        Arc::new(PseudoType),
        Arc::new(SimpleSuperOps { magic: 0x5045_5344, block_size: 4096, options: alloc::string::String::new() }),
        0x5045_5344, dev, 4096, alloc::string::String::from("pseudo-test"), Arc::new(()),
    )
}

#[test]
fn one_pseudo_template_gets_one_inode_view_per_superblock() {
    let root_template = InodeBuilder::new(6, mk_mode(FileType::Directory, 0o555),
        default_inode_ops(), default_file_ops()).build();
    let leaf_template = InodeBuilder::new(7, mk_mode(FileType::Regular, 0o444),
        default_inode_ops(), default_file_ops()).build();
    let first = superblock(101);
    let second = superblock(102);

    let first_root = crate::d_make_root(root_template.clone(), &first);
    let second_root = crate::d_make_root(root_template, &second);
    let first_inode = first_root.inode().expect("first root inode");
    let second_inode = second_root.inode().expect("second root inode");
    let first_leaf = crate::d_add(&first_root, "leaf", leaf_template.clone()).inode().expect("first leaf inode");
    let second_leaf = crate::d_add(&second_root, "leaf", leaf_template).inode().expect("second leaf inode");

    assert!(!Arc::ptr_eq(&first_inode, &second_inode), "each superblock has its own inode");
    assert!(first_inode.i_sb().is_some_and(|sb| Arc::ptr_eq(&sb, &first)));
    assert!(second_inode.i_sb().is_some_and(|sb| Arc::ptr_eq(&sb, &second)));
    assert!(!Arc::ptr_eq(&first_leaf, &second_leaf), "each lookup view has its own inode");
    assert!(first_leaf.i_sb().is_some_and(|sb| Arc::ptr_eq(&sb, &first)));
    assert!(second_leaf.i_sb().is_some_and(|sb| Arc::ptr_eq(&sb, &second)));
}
