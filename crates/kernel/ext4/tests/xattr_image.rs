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
        buffer: IMAGE.to_vec(),
    };
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
