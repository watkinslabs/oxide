use super::*;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::any::Any;
use vfs::{Dentry, FileType, Inode, InodeOps, KResult, VfsError};
use vfs::{InodeBuilder, default_file_ops, default_inode_ops, mk_mode};

struct DirData {
    kids: BTreeMap<String, InodeRef>,
}

struct DirOps;

impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}

fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids {
        m.insert(n.to_string(), i.clone());
    }
    let p: Arc<dyn Any + Send + Sync> = Arc::new(DirData { kids: m });
    InodeBuilder::new(
        ino,
        mk_mode(FileType::Directory, 0o755),
        Arc::new(DirOps),
        default_file_ops(),
    )
    .private(p)
    .build()
}

fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(
        ino,
        mk_mode(FileType::Regular, 0o644),
        default_inode_ops(),
        default_file_ops(),
    )
    .build()
}

fn sym(ino: u64, t: &str) -> InodeRef {
    InodeBuilder::new(
        ino,
        mk_mode(FileType::Symlink, 0o777),
        default_inode_ops(),
        default_file_ops(),
    )
    .size(t.len() as u64)
    .link(t.as_bytes().to_vec().into_boxed_slice() as Box<[u8]>)
    .build()
}

fn build_root() -> Arc<Dentry> {
    let root = dir(2, &[("target", file(11)), ("sl", sym(30, "target"))]);
    Dentry::new_root(root)
}

fn provider() -> Option<Arc<Dentry>> { Some(build_root()) }

#[test]
fn l_variant_does_not_follow_trailing_symlink() {
    vfs::set_root_dentry_provider(provider);
    let followed = resolve_str_inode("/sl", true).expect("follow resolves");
    assert_eq!(followed.file_type(), FileType::Regular);
    assert_eq!(followed.ino(), 11);
    let nofollow = resolve_str_inode("/sl", false).expect("nofollow resolves");
    assert_eq!(nofollow.file_type(), FileType::Symlink);
    assert_eq!(nofollow.ino(), 30);
}
