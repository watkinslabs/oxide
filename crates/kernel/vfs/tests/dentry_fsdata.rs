//! dcache-D26: `d_time` (fs-private revalidation stamp) + `d_fsdata`
//! (fs-private per-dentry token) live on the dentry (Linux `struct dentry`),
//! default 0, and round-trip through their accessors. These are the per-dentry
//! slots the owning fs uses for `d_revalidate`.

use std::sync::Arc;

use vfs::{Dentry, FileType, InodeRef};

fn dentry() -> Arc<Dentry> {
    let inode: InodeRef = vfs::InodeBuilder::new(0x1, vfs::mk_mode(FileType::Regular, 0o644), vfs::default_inode_ops(), vfs::default_file_ops()).build();
    Dentry::new(None, String::from("x"), inode)
}

#[test]
fn d_time_defaults_zero_and_roundtrips() {
    let d = dentry();
    assert_eq!(d.d_time(), 0, "d_time default 0");
    d.set_d_time(0xDEAD_BEEF);
    assert_eq!(d.d_time(), 0xDEAD_BEEF, "d_time round-trips");
}

#[test]
fn d_fsdata_defaults_zero_and_roundtrips() {
    let d = dentry();
    assert_eq!(d.d_fsdata(), 0, "d_fsdata default 0 (unset)");
    d.set_d_fsdata(0xC0DE);
    assert_eq!(d.d_fsdata(), 0xC0DE, "d_fsdata round-trips");
}

#[test]
fn d_time_and_d_fsdata_are_independent() {
    let d = dentry();
    d.set_d_time(11);
    d.set_d_fsdata(22);
    assert_eq!((d.d_time(), d.d_fsdata()), (11, 22), "independent slots");
}
