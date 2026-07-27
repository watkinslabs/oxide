use alloc::sync::Arc;
use std::collections::BTreeMap;

use vfs::{CreateCtx, Cred, Dentry, FileType, Inode, InodeBuilder, InodeOps,
          InodeRef, KResult, LookupFlags, VfsError, default_file_ops, mk_mode};

extern crate alloc;

struct DirData { kids: BTreeMap<&'static str, InodeRef> }
struct DirOps;

impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        inode.private::<DirData>().ok_or(VfsError::Enotdir)?
            .kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
    fn create(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio)
    }
    fn mkdir(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio)
    }
    fn symlink(&self, _inode: &Inode, _name: &str, _target: &[u8], _ctx: &CreateCtx) -> KResult<()> {
        Err(VfsError::Eio)
    }
}

fn cred(uid: u32) -> Cred {
    Cred {
        uid, gid: uid, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

fn reg(ino: u64, mode: u16, uid: u32) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, mode), vfs::default_inode_ops(), default_file_ops())
        .owner(uid, uid).build()
}

fn dir(ino: u64, mode: u16, uid: u32, kids: &[(&'static str, InodeRef)]) -> InodeRef {
    let mut map = BTreeMap::new();
    for (name, inode) in kids { map.insert(*name, inode.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, mode), Arc::new(DirOps), default_file_ops())
        .owner(uid, uid).private(Arc::new(DirData { kids: map })).build()
}

#[test]
fn access_lookup_uses_selected_cred_for_intermediate_dirs() {
    let leaf = reg(3, 0o644, 0);
    let gate = dir(2, 0o700, 2000, &[("leaf", leaf)]);
    let root_inode = dir(1, 0o755, 0, &[("gate", gate)]);
    let root = Dentry::new_root(root_inode);
    let real = cred(1000);
    let effective = cred(2000);

    let wrong_split_truth = vfs::path_lookup_at_root_cred(
        root.clone(), 0, root.clone(), 0, "/gate/leaf", LookupFlags::default(), effective.clone())
        .and_then(|p| vfs::inode_permission(&p.inode, vfs::MAY_READ, &real));
    assert_eq!(wrong_split_truth, Ok(()));

    let linux_access = vfs::path_lookup_at_root_cred(
        root.clone(), 0, root.clone(), 0, "/gate/leaf", LookupFlags::default(), real.clone())
        .and_then(|p| vfs::inode_permission(&p.inode, vfs::MAY_READ, &real));
    assert_eq!(linux_access, Err(VfsError::Eacces));

    let linux_faccessat2_eaccess = vfs::path_lookup_at_root_cred(
        root.clone(), 0, root.clone(), 0, "/gate/leaf", LookupFlags::default(), effective.clone())
        .and_then(|p| vfs::inode_permission(&p.inode, vfs::MAY_READ, &effective));
    assert_eq!(linux_faccessat2_eaccess, Ok(()));
}
