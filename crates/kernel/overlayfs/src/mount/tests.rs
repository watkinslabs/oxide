//! A whole mount, driven through the operations the VFS calls.
//!
//! These are the cases a container runtime produces: an image's layers below,
//! a writable layer on top, and every write landing there while the image
//! stays untouched. They go through the same entry points a syscall would,
//! so a wiring mistake — an operation that reaches the wrong layer, or one
//! that never copies up — fails here rather than on a boot.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::file_ops::{DirContext, DirEmit};
use vfs::inode_ops::CreateCtx;
use vfs::types::{FileType, S_IFREG};
use vfs::posix_acl::{to_xattr, AclEntry, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
                     ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ};
use vfs::fs::FileSystem;
use vfs::{Cred, GroupList, Iattr, InodeRef, VfsError, ATTR_MODE, MAY_READ, MAY_WRITE};

use crate::config::Config;
use crate::testfs::{layer, lookup as find_path, mkfile, mkpath, slurp};
use crate::whiteout;

use super::OverlayFs;

/// A resolver over named layers, standing in for the path walk a real mount
/// does.
struct Layers(BTreeMap<String, InodeRef>);

impl Layers {
    fn resolve(&self) -> impl Fn(&str) -> Result<InodeRef, Errno> + '_ {
        move |p: &str| self.0.get(p).cloned().ok_or(Errno::Enoent)
    }
}

/// An image layer, a writable layer and a work base, as a runtime lays them
/// out.
fn image() -> (Layers, InodeRef, InodeRef) {
    let up = layer(0);
    let lo = layer(1);
    let work = layer(2);
    let mut m = BTreeMap::new();
    m.insert("/upper".to_string(), up.clone());
    m.insert("/lower".to_string(), lo.clone());
    m.insert("/work".to_string(), work);
    (Layers(m), up, lo)
}

/// The names a directory shows through the overlay.
fn names(dir: &InodeRef) -> Vec<String> {
    struct Sink(Vec<String>);
    impl DirEmit for Sink {
        fn emit(&mut self, name: &str, _i: u64, _t: FileType, _n: u64) -> bool {
            self.0.push(name.to_string());
            true
        }
    }
    let mut sink = Sink(Vec::new());
    let mut ctx = DirContext::new(0, &mut sink);
    dir.readdir(&mut ctx).unwrap();
    sink.0.sort();
    sink.0
}

/// The option string a container runtime writes.
const OPTS: &str = "lowerdir=/lower,upperdir=/upper,workdir=/work";

#[test]
fn the_merged_root_shows_both_layers() {
    let (l, up, lo) = image();
    mkfile(&lo, "from-image", b"x");
    mkfile(&up, "from-writes", b"y");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    assert_eq!(names(&fs.root_inode()), vec!["from-image", "from-writes"]);
}

#[test]
fn a_lower_file_reads_through() {
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"image contents");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    let mut buf = [0u8; 32];
    let n = f.read(0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"image contents");
}

#[test]
fn repeated_lookup_returns_the_cached_overlay_inode() {
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"image contents");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let first = fs.root_inode().lookup("f").unwrap();
    let second = fs.root_inode().lookup("f").unwrap();
    assert!(Arc::ptr_eq(&first, &second), "one real object has one overlay inode");
}

#[test]
fn pure_upper_lookup_returns_the_cached_overlay_inode() {
    let (l, up, _lo) = image();
    mkfile(&up, "f", b"upper");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let first = fs.root_inode().lookup("f").unwrap();
    let second = fs.root_inode().lookup("f").unwrap();
    assert!(Arc::ptr_eq(&first, &second), "a pure upper object has one inode");
}

#[test]
fn nfs_export_round_trips_a_lower_handle_through_origin_state() {
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"lower");
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,nfs_export=on",
                             &l.resolve(), true).unwrap();
    let original = fs.root_inode().lookup("f").unwrap();
    let ops = fs.super_ops().unwrap();
    let mut bytes = vec![0u8; ops.export_fid_len(false, false) as usize];
    let (len, ty) = ops.export_encode_fh_raw(&original, None, &mut bytes);
    assert_eq!(ty, crate::uapi::OVERLAY_FILEID_V1);
    bytes.truncate(len as usize);
    let fid = ops.export_decode_fh_raw(&bytes, ty).unwrap();
    let sb = lo.i_sb().unwrap();
    let reopened = ops.fh_to_dentry_raw(&sb, &fid).unwrap();
    let mut data = [0u8; 8];
    let n = reopened.read(0, &mut data).unwrap();
    assert_eq!(&data[..n], b"lower");
}

#[test]
fn nfs_export_round_trips_a_pure_upper_handle() {
    let (l, up, _lo) = image();
    mkfile(&up, "f", b"upper");
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,nfs_export=on",
                             &l.resolve(), true).unwrap();
    let original = fs.root_inode().lookup("f").unwrap();
    let ops = fs.super_ops().unwrap();
    let mut bytes = vec![0u8; ops.export_fid_len(false, false) as usize];
    let (len, ty) = ops.export_encode_fh_raw(&original, None, &mut bytes);
    bytes.truncate(len as usize);
    assert!(crate::fh::decode(&bytes).unwrap().is_upper);
    let fid = ops.export_decode_fh_raw(&bytes, ty).unwrap();
    let sb = up.i_sb().unwrap();
    let reopened = ops.fh_to_dentry_raw(&sb, &fid).unwrap();
    let mut data = [0u8; 8];
    let n = reopened.read(0, &mut data).unwrap();
    assert_eq!(&data[..n], b"upper");
}

#[test]
fn nfs_export_rejects_connectable_overlay_handles() {
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"lower");
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,nfs_export=on",
                             &l.resolve(), true).unwrap();
    let inode = fs.root_inode().lookup("f").unwrap();
    let ops = fs.super_ops().unwrap();
    let mut bytes = vec![0u8; ops.export_fid_len(true, false) as usize];
    let (len, ty) = ops.export_encode_fh_raw(&inode, Some((1, 1)), &mut bytes);
    assert_eq!((len, ty), (0, -1));
}

#[test]
fn indexed_lower_hardlinks_share_one_overlay_inode() {
    let (l, _up, lo) = image();
    let first = mkfile(&lo, "a", b"image");
    lo.link_child(&first, "b", &CreateCtx::root()).unwrap();
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,index=on",
                             &l.resolve(), true).unwrap();
    let a = fs.root_inode().lookup("a").unwrap();
    let b = fs.root_inode().lookup("b").unwrap();
    assert!(Arc::ptr_eq(&a, &b), "indexed hardlinks use one real inode key");
}

#[test]
fn writing_a_lower_file_copies_it_up_and_leaves_the_image_alone() {
    let (l, up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    f.write(0, b"local").unwrap();
    assert_eq!(slurp(&find_path(&up, "f").expect("copied up")), b"local".to_vec());
    assert_eq!(slurp(&find_path(&lo, "f").unwrap()), b"image".to_vec());
    let mut buf = [0u8; 16];
    let n = f.read(0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"local");
}

#[test]
fn fallocate_on_a_lower_file_copies_data_up_before_forwarding() {
    let (l, up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    f.fallocate(0, 4096, 4096).unwrap();
    assert_eq!(f.size(), 8192);
    assert_eq!(slurp(&find_path(&lo, "f").unwrap()), b"image".to_vec());
    assert_eq!(find_path(&up, "f").unwrap().size(), 8192);
}

#[test]
fn fiemap_on_a_metadata_only_file_reads_the_data_owner() {
    let (l, up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,metacopy=on",
                             &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    let mut extents = Vec::new();
    f.fiemap(0, 4096, &mut |e| { extents.push(e); true }).unwrap();
    assert_eq!(extents.len(), 1);
    assert!(find_path(&up, "f").is_none(), "fiemap is read-only");
    assert_eq!(slurp(&find_path(&lo, "f").unwrap()), b"image".to_vec());
}

#[test]
fn overlay_tmpfile_is_unlinked_until_linked_into_the_upper_layer() {
    let (l, up, _lo) = image();
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let tmp = fs.root_inode().tmpfile(S_IFREG as u32 | 0o600, &CreateCtx::root()).unwrap();
    assert_eq!(tmp.nlink(), 0);
    tmp.write(0, b"anonymous").unwrap();
    fs.root_inode().link_child(&tmp, "published", &CreateCtx::root()).unwrap();
    assert_eq!(slurp(&find_path(&up, "published").unwrap()), b"anonymous".to_vec());
}

#[test]
fn creating_a_file_lands_in_the_writable_layer_only() {
    let (l, up, lo) = image();
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    fs.root_inode().create_child("new", S_IFREG as u32 | 0o644, &CreateCtx::root()).unwrap();
    assert!(find_path(&up, "new").is_some());
    assert!(find_path(&lo, "new").is_none());
}

#[test]
fn deleting_a_lower_file_hides_it_without_touching_the_image() {
    let (l, up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    fs.root_inode().unlink_child("f").unwrap();
    assert!(fs.root_inode().lookup("f").is_err());
    assert!(whiteout::is_device(&find_path(&up, "f").unwrap()));
    assert!(find_path(&lo, "f").is_some(), "the image is read-only");
    assert!(names(&fs.root_inode()).is_empty());
}

#[test]
fn a_write_deep_in_the_image_copies_up_the_directories_above_it() {
    // A container writing one configuration file must not copy the tree it
    // sits in, but the directories themselves have to exist above it.
    let (l, up, lo) = image();
    mkfile(&lo, "etc/nested/conf", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let etc = fs.root_inode().lookup("etc").unwrap();
    let nested = etc.lookup("nested").unwrap();
    let conf = nested.lookup("conf").unwrap();
    conf.write(0, b"local").unwrap();
    assert_eq!(find_path(&up, "etc").unwrap().file_type(), FileType::Directory);
    assert_eq!(slurp(&find_path(&up, "etc/nested/conf").unwrap()), b"local".to_vec());
    assert_eq!(slurp(&find_path(&lo, "etc/nested/conf").unwrap()), b"image".to_vec());
}

#[test]
fn a_merged_directory_lists_every_layer_and_hides_what_was_deleted() {
    let (l, _up, lo) = image();
    mkfile(&lo, "d/a", b"");
    mkfile(&lo, "d/b", b"");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let d = fs.root_inode().lookup("d").unwrap();
    d.create_child("c", S_IFREG as u32 | 0o644, &CreateCtx::root()).unwrap();
    assert_eq!(names(&d), vec!["a", "b", "c"]);
    d.unlink_child("a").unwrap();
    assert_eq!(names(&d), vec!["b", "c"]);
}

#[test]
fn the_overlays_own_markers_are_invisible_to_a_caller() {
    // Listing one would make a `tar` of the overlay carry it into the archive,
    // and restoring that produces a file nothing can see.
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"x");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    f.setxattr("user.mine", b"v".to_vec(), false, false).unwrap();
    let listed = f.listxattr().unwrap();
    assert!(listed.contains(&"user.mine".to_string()));
    assert!(!listed.iter().any(|n| n.starts_with("trusted.overlay.")), "{listed:?}");
    assert!(f.setxattr("trusted.overlay.opaque", b"y".to_vec(), false, false).is_err());
}

#[test]
fn chmod_forwards_the_acl_rewrite_to_the_copied_up_inode() {
    let (l, up, lo) = image();
    let lower = mkfile(&lo, "acl", b"image");
    let entry = |tag, perm, id| AclEntry { tag, perm, id };
    lower.setxattr("system.posix_acl_access", to_xattr(&[
        entry(ACL_USER_OBJ, 0o6, ACL_UNDEFINED_ID),
        entry(ACL_USER, 0o6, 1000),
        entry(ACL_GROUP_OBJ, 0o4, ACL_UNDEFINED_ID),
        entry(ACL_MASK, 0o6, ACL_UNDEFINED_ID),
        entry(ACL_OTHER, 0o4, ACL_UNDEFINED_ID),
    ]), false, false).expect("set lower acl");
    let user = Cred { uid: 1000, gid: 9, cap_dac_override: false, cap_dac_read_search: false,
                      cap_fowner: false, cap_chown: false, cap_fsetid: false,
                      groups: GroupList::empty() };
    assert_eq!(lower.permission(MAY_READ | MAY_WRITE, &user), Ok(()));

    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let over = fs.root_inode().lookup("acl").unwrap();
    over.setattr(&vfs::IDENTITY,
                 &Iattr { valid: ATTR_MODE, mode: 0o600, ..Iattr::default() })
        .expect("overlay chmod");

    assert_eq!(over.permission(MAY_READ, &user), Err(VfsError::Eacces));
    let upper = find_path(&up, "acl").expect("copied-up inode");
    assert_eq!(upper.permission(MAY_READ, &user), Err(VfsError::Eacces));
    let upper_acl = upper.getxattr("system.posix_acl_access").expect("upper keeps ACL");
    let upper_acl = vfs::posix_acl::from_xattr(&upper_acl).expect("decode upper ACL");
    assert_eq!(upper_acl.iter().find(|e| e.tag == ACL_MASK).unwrap().perm, 0,
               "the forwarded chmod must rewrite the copied-up ACL");
    assert_eq!(lower.permission(MAY_READ | MAY_WRITE, &user), Ok(()),
               "copy-up must not mutate the image layer's ACL");
}

#[test]
fn override_creds_uses_the_mount_owner_for_the_real_layer_check() {
    let (l, _up, lo) = image();
    let lower = mkfile(&lo, "private", b"image");
    lower.set_perm(0).unwrap();
    let mounter = Cred { uid: 1000, gid: 1000, cap_dac_override: false,
        cap_dac_read_search: false, cap_fowner: false, cap_chown: false,
        cap_fsetid: false, groups: GroupList::empty() };
    let caller = Cred { uid: 2000, gid: 2000, cap_dac_override: false,
        cap_dac_read_search: true, cap_fowner: false, cap_chown: false,
        cap_fsetid: false, groups: GroupList::empty() };
    let fs = OverlayFs::open_with_cred(OPTS, &l.resolve(), true, &mounter).unwrap();
    let f = fs.root_inode().lookup("private").unwrap();
    assert_eq!(f.permission(MAY_READ, &caller), Err(VfsError::Eacces));
}

#[test]
fn nooverride_creds_uses_the_requesting_task_for_the_real_layer_check() {
    let (l, _up, lo) = image();
    let lower = mkfile(&lo, "private", b"image");
    lower.set_perm(0).unwrap();
    let mounter = Cred { uid: 1000, gid: 1000, cap_dac_override: false,
        cap_dac_read_search: false, cap_fowner: false, cap_chown: false,
        cap_fsetid: false, groups: GroupList::empty() };
    let caller = Cred { uid: 2000, gid: 2000, cap_dac_override: false,
        cap_dac_read_search: true, cap_fowner: false, cap_chown: false,
        cap_fsetid: false, groups: GroupList::empty() };
    let fs = OverlayFs::open_with_cred(
        "lowerdir=/lower,upperdir=/upper,workdir=/work,nooverride_creds",
        &l.resolve(), true, &mounter).unwrap();
    let f = fs.root_inode().lookup("private").unwrap();
    assert_eq!(f.permission(MAY_READ, &caller), Ok(()));
}

#[test]
fn a_read_only_overlay_of_two_image_layers_merges_them() {
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    mkfile(&l1, "a", b"one");
    mkfile(&l2, "b", b"two");
    let mut m = BTreeMap::new();
    m.insert("/l1".to_string(), l1);
    m.insert("/l2".to_string(), l2);
    let l = Layers(m);
    let fs = OverlayFs::open("lowerdir=/l1:/l2", &l.resolve(), true).unwrap();
    assert!(!fs.writable());
    assert_eq!(names(&fs.root_inode()), vec!["a", "b"]);
    let _ = up;
}

#[test]
fn a_work_directory_inside_the_writable_layer_is_refused() {
    let (l, _up, _lo) = image();
    let opts = "lowerdir=/lower,upperdir=/upper,workdir=/upper/work";
    assert_eq!(OverlayFs::open(opts, &l.resolve(), true).err(), Some(Errno::Einval));
}

#[test]
fn a_layer_that_is_not_a_directory_is_refused() {
    let (mut l, _up, lo) = image();
    let f = mkfile(&lo, "file", b"x");
    l.0.insert("/notadir".to_string(), f);
    let opts = "lowerdir=/notadir,upperdir=/upper,workdir=/work";
    assert_eq!(OverlayFs::open(opts, &l.resolve(), true).err(), Some(Errno::Enotdir));
}

#[test]
fn a_layer_that_does_not_exist_is_refused() {
    let (l, _up, _lo) = image();
    let opts = "lowerdir=/absent,upperdir=/upper,workdir=/work";
    assert_eq!(OverlayFs::open(opts, &l.resolve(), true).err(), Some(Errno::Enoent));
}

#[test]
fn a_single_lower_layer_with_nothing_to_write_to_is_refused() {
    // It would present the layer unchanged and fail every write in a way the
    // caller cannot tell from a broken mount.
    let (l, _up, _lo) = image();
    assert_eq!(OverlayFs::open("lowerdir=/lower", &l.resolve(), true).err(), Some(Errno::Einval));
}

#[test]
fn a_mount_with_no_layers_at_all_is_refused() {
    let (l, _up, _lo) = image();
    assert_eq!(OverlayFs::open("", &l.resolve(), true).err(), Some(Errno::Einval));
}

#[test]
fn the_work_directory_is_created_under_the_named_base() {
    let (l, _up, _lo) = image();
    OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let work = l.0.get("/work").unwrap();
    assert!(find_path(work, "work").is_some());
}

#[test]
fn a_volatile_mount_publishes_the_incompatibility_marker() {
    let (l, _up, _lo) = image();
    OverlayFs::open(&alloc::format!("{OPTS},volatile"), &l.resolve(), true).unwrap();
    let base = l.0.get("/work").unwrap();
    let work = find_path(base, crate::uapi::WORKDIR_NAME).unwrap();
    assert!(find_path(&work, crate::uapi::VOLATILE_DIRTY_NAME).is_some());
}

#[test]
fn a_mount_refuses_a_workdir_with_a_volatile_incompatibility_marker() {
    let (l, _up, _lo) = image();
    let base = l.0.get("/work").unwrap();
    let work = mkpath(base, crate::uapi::WORKDIR_NAME);
    mkfile(&work, crate::uapi::VOLATILE_DIRTY_NAME, b"");
    assert_eq!(OverlayFs::open(OPTS, &l.resolve(), true).err(), Some(Errno::Einval));
}

#[test]
fn a_mount_removes_a_malformed_index_entry_before_publishing_root() {
    let (l, _up, _lo) = image();
    let base = l.0.get("/work").unwrap();
    let index = mkpath(base, "index");
    mkfile(&index, "not-an-origin-handle", b"");
    assert!(names(&index).contains(&"not-an-origin-handle".to_string()));
    let opts = "lowerdir=/lower,upperdir=/upper,workdir=/work,index=on";
    let fs = OverlayFs::open(opts, &l.resolve(), true).unwrap();
    assert!(fs.layers().indexdir.is_some());
    assert!(index.lookup("not-an-origin-handle").is_err(),
            "mount must clean an index entry it cannot decode");
}

#[test]
fn the_mount_line_names_the_layers_back() {
    let (l, _up, _lo) = image();
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let line = vfs::fs::FileSystem::show_options(&*fs);
    assert!(line.contains("lowerdir=/lower"), "{line}");
    assert!(line.contains("upperdir=/upper"), "{line}");
    assert!(line.contains("workdir=/work"), "{line}");
}

#[test]
fn the_mount_line_escapes_the_verbatim_lowerdir_list_again() {
    let up = layer(0);
    let lo = layer(1);
    let work = layer(2);
    let mut m = BTreeMap::new();
    m.insert("/upper".to_string(), up);
    m.insert("/a,b".to_string(), lo);
    m.insert("/work".to_string(), work);
    let l = Layers(m);
    let fs = OverlayFs::open("lowerdir=/a\\,b,upperdir=/upper,workdir=/work",
        &l.resolve(), true).unwrap();
    let line = vfs::fs::FileSystem::show_options(&*fs);
    assert!(line.contains("lowerdir=/a\\\\\\,b"), "{line}");
}

#[test]
fn the_reported_filesystem_type_is_the_overlays() {
    let (l, _up, _lo) = image();
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let ops = vfs::fs::FileSystem::super_ops(&*fs).unwrap();
    assert_eq!(ops.statfs().unwrap().f_type, super::OVERLAYFS_SUPER_MAGIC);
    assert_eq!(vfs::fs::FileSystem::magic(&*fs), super::OVERLAYFS_SUPER_MAGIC);
}

#[test]
fn a_copied_up_file_keeps_the_inode_number_it_had() {
    // A program holding the file open across a write must not see its identity
    // change under it.
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let before = fs.root_inode().lookup("f").unwrap().ino();
    let f = fs.root_inode().lookup("f").unwrap();
    f.write(0, b"local").unwrap();
    let after = fs.root_inode().lookup("f").unwrap().ino();
    assert_eq!(before, after);
    let _ = mkpath(&lo, "unused");
    let _ = Config::default();
    let _ = Arc::new(());
    let _ = vec![0u8; 0];
}
