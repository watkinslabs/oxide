use super::{Dentry, InodeRef, MemFile};
use alloc::string::String;
use alloc::sync::Arc;

#[test]
fn dentry_roundtrip_positive_negative() {
    let i: InodeRef = MemFile::new(1);
    let d = Dentry::new_root(Arc::clone(&i));
    assert_eq!(d.name(), "");
    assert!(d.parent().is_none());
    assert!(!d.is_negative());
    assert!(d.inode().is_some());

    let neg = Dentry::new_negative(Some(Arc::clone(&d)), String::from("missing"));
    assert!(neg.is_negative());
    assert_eq!(neg.name(), "missing");
    assert!(neg.inode().is_none());

    neg.set_inode(Some(MemFile::new(2)));
    assert!(!neg.is_negative());
}

#[test]
fn dentry_absolute_path_root_is_slash() {
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(i);
    assert_eq!(root.absolute_path(), b"/");
}

#[test]
fn dentry_absolute_path_single_component() {
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(Arc::clone(&i));
    let bin  = Dentry::new(Some(root), String::from("bin"), Arc::clone(&i));
    assert_eq!(bin.absolute_path(), b"/bin");
}

#[test]
fn dentry_absolute_path_nested_components() {
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(Arc::clone(&i));
    let sbin = Dentry::new(Some(root),           String::from("sbin"), Arc::clone(&i));
    let exe  = Dentry::new(Some(Arc::clone(&sbin)), String::from("init"), Arc::clone(&i));
    assert_eq!(exe.absolute_path(), b"/sbin/init");
}

#[test]
fn dentry_absolute_path_open_dentry_shape() {
    // WP2: an opened file's dentry is parented; a whole path in one name is not
    // a shape built by the open path.
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(Arc::clone(&i));
    let dev  = Dentry::new(Some(root),            String::from("dev"), Arc::clone(&i));
    let pts  = Dentry::new(Some(Arc::clone(&dev)), String::from("pts"), Arc::clone(&i));
    let three = Dentry::new_child(&pts, "3", Some(Arc::clone(&i)));
    assert_eq!(three.absolute_path(), b"/dev/pts/3");
}

#[test]
fn dentry_absolute_path_deep_chain() {
    let i: InodeRef = MemFile::new(1);
    let root = Dentry::new_root(Arc::clone(&i));
    let a    = Dentry::new(Some(root),            String::from("usr"),   Arc::clone(&i));
    let b    = Dentry::new(Some(Arc::clone(&a)),  String::from("share"), Arc::clone(&i));
    let c    = Dentry::new(Some(Arc::clone(&b)),  String::from("zoneinfo"), Arc::clone(&i));
    let leaf = Dentry::new(Some(Arc::clone(&c)),  String::from("UTC"),   Arc::clone(&i));
    assert_eq!(leaf.absolute_path(), b"/usr/share/zoneinfo/UTC");
}
