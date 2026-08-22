//! D45 ext4 on-disk xattr persistence: a `setxattr` is written to the inode's
//! on-disk IBODY area, so it survives inode eviction + remount (disk is the
//! authority, the in-core `SimpleXattrs` store is just the cache).

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

// One shared MemDisk holding the image; both mounts read/write the SAME device,
// so a write from mount #1 is visible to a fresh mount #2 (remount).
fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

// Set xattrs on a file, then re-mount the SAME disk (forces a fresh inode object
// + a fresh SimpleXattrs store populated only from disk) and read them back.
#[test]
fn ibody_xattr_persists_across_remount() {
    let disk = build_disk();
    let path = b"/xattr.bin";

    // Mount #1: create file, set two xattrs (security.* + user.*).
    {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
        let st = m.state();
        let inode = st.create_at(path, 0o644).expect("create");
        inode.setxattr("security.selinux", b"system_u:object_r:etc_t:s0\0".to_vec(), false, false)
            .expect("setxattr security.selinux");
        inode.setxattr("user.comment", b"hello-disk".to_vec(), false, false)
            .expect("setxattr user.comment");
        // In-core read-back (sanity before eviction).
        assert_eq!(inode.getxattr("user.comment").unwrap(), b"hello-disk");
    }

    // Mount #2: fresh mount of the same device — the inode + its xattr store are
    // rebuilt purely from disk. If persistence works, the xattrs are present.
    {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
        let st = m.state();
        let inode = st.lookup_inode_any(path).expect("lookup after remount");
        assert_eq!(inode.getxattr("security.selinux").unwrap(),
                   b"system_u:object_r:etc_t:s0\0".to_vec(),
                   "security.selinux must survive eviction + remount (read from disk ibody)");
        assert_eq!(inode.getxattr("user.comment").unwrap(), b"hello-disk".to_vec(),
                   "user.comment must survive eviction + remount");
        let mut names = inode.listxattr().unwrap();
        names.sort();
        assert_eq!(names, alloc::vec![
            alloc::string::String::from("security.selinux"),
            alloc::string::String::from("user.comment"),
        ]);
    }
}

// removexattr must also reach disk: after removing one of two attrs and
// remounting, only the survivor is present.
#[test]
fn removexattr_persists_across_remount() {
    let disk = build_disk();
    let path = b"/rm.bin";

    {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
        let st = m.state();
        let inode = st.create_at(path, 0o644).expect("create");
        inode.setxattr("user.a", b"1".to_vec(), false, false).unwrap();
        inode.setxattr("user.b", b"2".to_vec(), false, false).unwrap();
        inode.removexattr("user.a").expect("removexattr user.a");
    }

    {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
        let st = m.state();
        let inode = st.lookup_inode_any(path).expect("lookup after remount");
        assert!(inode.getxattr("user.a").is_err(), "removed attr must not be on disk");
        assert_eq!(inode.getxattr("user.b").unwrap(), b"2".to_vec(), "survivor persists");
    }
}

// CONSERVATIVE check: an inode that never had an xattr set is NOT rewritten by
// the xattr path — its on-disk inode slot stays byte-identical. We compare the
// raw inode bytes of a freshly-created (no-xattr) file before vs. after merely
// igeting it (which runs the load path), proving load-on-iget is read-only.
#[test]
fn no_xattr_inode_slot_unchanged_by_load() {
    let disk = build_disk();
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
    let st = m.state();
    let _inode = st.create_at(b"/plain.bin", 0o644).expect("create");
    let ino = st.lookup_path(b"/plain.bin").expect("resolve");

    let (before, _off) = st.mount.read_inode_bytes(ino).expect("read before");
    // iget again (runs load_xattrs) + a getxattr that finds nothing.
    let inode = st.lookup_inode_any(b"/plain.bin").expect("lookup");
    assert!(inode.getxattr("user.none").is_err(), "no xattr present");
    let (after, _off2) = st.mount.read_inode_bytes(ino).expect("read after");
    assert_eq!(before, after, "no-xattr inode slot must be byte-identical (load is read-only)");
}

// The xattr SYSCALL layer (`fs::xattr`, the Linux `vfs_setxattr` policy half)
// over an ext4 inode: the namespace/permission rules run, and the value the
// policy layer accepts reaches DISK, surviving inode eviction + remount. This
// is the end-to-end answer to "does ext4 really persist xattrs" — the store the
// syscall writes is the on-disk ibody/xattr-block, not an in-core side table.
#[test]
fn syscall_layer_policy_writes_reach_disk_on_ext4() {
    let disk = build_disk();
    let path = b"/policy.bin";
    let root = fs::xattr::XattrCred::root();
    let unpriv = fs::xattr::XattrCred {
        cred: vfs::Cred { uid: 1000, gid: 1000, cap_dac_override: false,
                          cap_dac_read_search: false, cap_fowner: false, cap_chown: false,
                          cap_fsetid: false, groups: vfs::GroupList::empty() },
        sys_admin: false, setfcap: false,
    };

    {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
        let st = m.state();
        let inode = st.create_at(path, 0o666).expect("create");
        // trusted.* needs CAP_SYS_ADMIN; security.* likewise; user.* takes DAC.
        assert_eq!(fs::xattr::vfs_setxattr(&inode, "trusted.t", b"p".to_vec(), 0, &unpriv),
                   Err(-(1)), "trusted.* without CAP_SYS_ADMIN is EPERM");
        assert_eq!(fs::xattr::vfs_setxattr(&inode, "trusted.t", b"p".to_vec(), 0, &root), Ok(()));
        assert_eq!(fs::xattr::vfs_setxattr(&inode, "user.c", b"disk".to_vec(), 0, &unpriv), Ok(()));
        // An unsupported namespace is EOPNOTSUPP and stores nothing.
        assert_eq!(fs::xattr::vfs_setxattr(&inode, "btrfs.x", b"n".to_vec(), 0, &root), Err(-95));
    }

    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
    let st = m.state();
    let inode = st.lookup_inode_any(path).expect("lookup after remount");
    assert_eq!(fs::xattr::vfs_getxattr(&inode, "user.c", &root), Ok(b"disk".to_vec()));
    assert_eq!(fs::xattr::vfs_getxattr(&inode, "trusted.t", &root), Ok(b"p".to_vec()));
    // trusted.* stays hidden from an unprivileged reader, on disk or not.
    assert_eq!(fs::xattr::vfs_getxattr(&inode, "trusted.t", &unpriv), Err(-61));
    assert_eq!(fs::xattr::vfs_listxattr(&inode, &unpriv), Ok(b"user.c\0".to_vec()));
    assert_eq!(fs::xattr::vfs_listxattr(&inode, &root), Ok(b"trusted.t\0user.c\0".to_vec()));
    assert_eq!(fs::xattr::vfs_getxattr(&inode, "btrfs.x", &root), Err(-95));
}

// A POSIX ACL is stored as this filesystem's own record — version 1 with
// variable-length entries — not as the interchange blob a caller sets and gets.
// Storing the blob verbatim would write a version this format's reader rejects,
// so a Linux `getfacl` would refuse it and the permission check could not decode
// the ACL that is meant to decide it.
#[test]
fn a_posix_acl_is_stored_as_the_on_disk_record_and_not_the_interchange_blob() {
    use vfs::posix_acl::{disk, from_xattr, to_xattr, AclEntry, ACL_GROUP_OBJ, ACL_MASK,
                         ACL_OTHER, ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ};
    let disk_dev = build_disk();
    let path = b"/acl.bin";
    let blob = to_xattr(&[
        AclEntry { tag: ACL_USER_OBJ, perm: 0o6, id: ACL_UNDEFINED_ID },
        AclEntry { tag: ACL_USER, perm: 0o6, id: 1000 },
        AclEntry { tag: ACL_GROUP_OBJ, perm: 0o4, id: ACL_UNDEFINED_ID },
        AclEntry { tag: ACL_MASK, perm: 0o6, id: ACL_UNDEFINED_ID },
        AclEntry { tag: ACL_OTHER, perm: 0o4, id: ACL_UNDEFINED_ID },
    ]);
    let record = disk::to_disk(&from_xattr(&blob).unwrap()).unwrap();
    assert_ne!(record, blob, "the two forms are different bytes, so this can fail");

    let m = ext4::rootfs::Ext4Mount::open(disk_dev.clone()).unwrap();
    let st = m.state();
    let inode = st.create_at(path, 0o640).expect("create");
    inode.setxattr("system.posix_acl_access", blob.clone(), false, false).expect("set acl");
    // The value the medium holds, read past the converting boundary.
    assert_eq!(inode.simple_xattrs().unwrap().get("system.posix_acl_access").unwrap(), record,
               "the interchange blob must not be stored verbatim");
    // And what a caller gets back is the blob again.
    assert_eq!(inode.getxattr("system.posix_acl_access").unwrap(), blob);
    // Which is also what the permission check decodes.
    let got = inode.get_inode_acl(vfs::posix_acl::AclType::Access).expect("decode").expect("some");
    assert_eq!(got.len(), 5);
    assert_eq!(got[1], AclEntry { tag: ACL_USER, perm: 0o6, id: 1000 });
}

#[test]
fn chmod_narrows_the_acl_and_the_narrowing_survives_remount() {
    use vfs::posix_acl::{from_xattr, to_xattr, AclEntry, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
                         ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ};
    use vfs::{Cred, GroupList, Iattr, VfsError, ATTR_MODE, MAY_READ, MAY_WRITE};

    let entry = |tag, perm, id| AclEntry { tag, perm, id };
    let acl = to_xattr(&[
        entry(ACL_USER_OBJ, 0o6, ACL_UNDEFINED_ID),
        entry(ACL_USER, 0o6, 1000),
        entry(ACL_GROUP_OBJ, 0o4, ACL_UNDEFINED_ID),
        entry(ACL_MASK, 0o6, ACL_UNDEFINED_ID),
        entry(ACL_OTHER, 0o4, ACL_UNDEFINED_ID),
    ]);
    let user = Cred { uid: 1000, gid: 9, cap_dac_override: false, cap_dac_read_search: false,
                      cap_fowner: false, cap_chown: false, cap_fsetid: false,
                      groups: GroupList::empty() };
    let disk = build_disk();
    let path = b"/acl-chmod.bin";

    {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
        let inode = m.state().create_at(path, 0o664).expect("create");
        inode.setxattr("system.posix_acl_access", acl, false, false).expect("set acl");
        assert_eq!(inode.permission(MAY_READ | MAY_WRITE, &user), Ok(()));
        inode.setattr(&vfs::IDENTITY,
                      &Iattr { valid: ATTR_MODE, mode: 0o600, ..Iattr::default() })
            .expect("chmod");
        assert_eq!(inode.permission(MAY_READ, &user), Err(VfsError::Eacces));
    }

    let m = ext4::rootfs::Ext4Mount::open(disk).unwrap();
    let inode = m.state().lookup_inode_any(path).expect("remount lookup");
    assert_eq!(inode.permission(MAY_READ, &user), Err(VfsError::Eacces));
    let stored = inode.getxattr("system.posix_acl_access").expect("stored acl");
    let entries = from_xattr(&stored).expect("decode acl");
    assert_eq!(entries.iter().find(|e| e.tag == ACL_MASK).unwrap().perm, 0);
}
