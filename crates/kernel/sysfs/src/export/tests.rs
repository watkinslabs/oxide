use vfs::fs::FileSystem;
use vfs::SuperOps;
use vfs::export::kernfs_fid::{HANDLE_TYPE_KERNFS, KERNFS_FID_LEN};

use super::*;

#[test]
fn a_sysfs_handle_round_trips_through_the_live_kernfs_tree() {
    crate::register("/sys/export-test/handle",
        crate::make_body_inode(b"handle\n".to_vec(), 0x51ee_0001));
    let ops = crate::SysfsFs.super_ops().expect("sysfs installs export operations");
    let inode = crate::sys_root().lookup_path("export-test/handle").expect("published node");

    assert!(ops.export_can_decode_fh());
    let mut bytes = [0u8; KERNFS_FID_LEN as usize];
    let (len, kind) = ops.export_encode_fh(&inode, None, &mut bytes);
    assert_eq!((len, kind), (KERNFS_FID_LEN, HANDLE_TYPE_KERNFS));
    let fid = ops.export_decode_fh(&bytes, kind).expect("handle decodes");
    let back = crate::sys_root().find_ino(fid.ino).expect("handle reconnects");
    assert_eq!(back.ino(), inode.ino());
}

#[test]
fn an_unknown_sysfs_node_id_is_stale() {
    assert!(crate::sys_root().find_ino(u64::MAX).is_none());
    assert_eq!(
        SysfsSuperOps.export_decode_fh(&[0u8; KERNFS_FID_LEN as usize], 0),
        Err(syscall::errno::Errno::Estale),
    );
}
