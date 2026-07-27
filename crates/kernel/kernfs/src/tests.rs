use alloc::string::String;
use alloc::sync::Arc;

use vfs::superblock::SuperBlock;
use vfs::{FileType, Ino};

use crate::{PSEUDO_ROOT_INO, PseudoDir, PseudoFs, PseudoSymlink, dir_ino};

/// Build a superblock for `fs`, the way a real kernfs consumer does at mount.
/// `superblock_from_filesystem` is the successor to the removed
/// `SuperBlock::for_backend`: it picks up the fs's own `super_ops`, builds the
/// root via `d_make_root`, and — critically for these tests — calls `set_sb`,
/// which is what puts the fs's inodes into THIS superblock's icache. Without
/// that link the icache assertions below would pass vacuously against an
/// unrelated empty cache.
fn test_sb(fs: &Arc<PseudoFs>, root_inode: vfs::InodeRef) -> Arc<SuperBlock> {
    use vfs::fs::{FileSystem, FsFlags, FsType};
    let ty: Arc<dyn vfs::FileSystemType> = FsType::new(
        "kernfs", 0xBEEF, FsFlags::empty(),
        alloc::boxed::Box::new(|_, _, _, _| unreachable!("test fs type is not mounted through ->mount")),
    );
    vfs::fs::superblock_from_filesystem(
        ty, fs.clone() as Arc<dyn FileSystem>, Some(root_inode), String::from("kernfs"),
    ).expect("kernfs test superblock")
}

fn root() -> Arc<PseudoDir> {
    PseudoDir::new_root(0x5000_0001, 0xDEAD)
}

#[test]
fn insert_then_lookup_per_component() {
    let r = root();
    let leaf = PseudoSymlink::new(1, 0xDEAD, b"/target");
    r.insert_path("/sys/kernel/osrelease", leaf);
    let got = r.lookup_path("/sys/kernel/osrelease").expect("leaf");
    assert_eq!(got.file_type(), FileType::Symlink);
    let kdir = r.lookup_path("/sys/kernel").expect("intermediate dir");
    assert_eq!(kdir.file_type(), FileType::Directory);
    let sys = r.as_inode().lookup("sys").expect("sys child");
    assert_eq!(sys.lookup("kernel").expect("kernel child").file_type(), FileType::Directory);
}

#[test]
fn leaf_mid_path_is_none() {
    let r = root();
    r.insert_path("/a/b", PseudoSymlink::new(2, 0, b"x"));
    assert!(r.lookup_path("/a/b/c").is_none());
}

#[test]
fn readdir_sorted_and_no_overlay_when_off() {
    let r = root();
    r.insert_path("/z", PseudoSymlink::new(3, 0, b"z"));
    r.insert_path("/a", PseudoSymlink::new(4, 0, b"a"));
    r.insert_path("/m", PseudoSymlink::new(5, 0, b"m"));
    let mut names = std::vec::Vec::new();
    {
        struct Collect<'a>(&'a mut std::vec::Vec<std::string::String>);
        impl<'a> vfs::DirEmit for Collect<'a> {
            fn emit(&mut self, name: &str, _ino: u64, _d: vfs::FileType, _next: u64) -> bool {
                self.0.push(std::string::String::from(name));
                true
            }
        }
        let mut actor = Collect(&mut names);
        let mut ctx = vfs::DirContext::new(0, &mut actor);
        r.as_inode().readdir(&mut ctx).unwrap();
    }
    assert_eq!(names, std::vec!["a", "m", "z"]);
}

#[test]
fn ensure_dir_path_creates_empty_mountpoint() {
    let r = root();
    r.ensure_dir_path("/sys/fs/cgroup");
    let d = r.lookup_path("/sys/fs/cgroup").expect("mountpoint dir");
    assert_eq!(d.file_type(), FileType::Directory);
}

#[test]
fn deep_clone_is_independent() {
    let r = root();
    r.insert_path("/dev/null", PseudoSymlink::new(6, 0, b"n"));
    let c = r.deep_clone();
    c.insert_path("/dev/extra", PseudoSymlink::new(7, 0, b"e"));
    assert!(c.lookup_path("/dev/extra").is_some());
    assert!(r.lookup_path("/dev/extra").is_none());
    assert!(r.lookup_path("/dev/null").is_some());
    assert!(c.lookup_path("/dev/null").is_some());
}

#[test]
fn own_roots_are_isolated() {
    let sys = PseudoDir::new_root(dir_ino("/sys"), 0x2);
    let trace = PseudoDir::new_root(dir_ino("/sys/kernel/tracing"), 0x3);
    sys.insert_path("class/net", PseudoSymlink::new(10, 0x2, b"net"));
    sys.insert_path("kernel/osrelease", PseudoSymlink::new(11, 0x2, b"v"));
    trace.insert_path("current_tracer", PseudoSymlink::new(12, 0x3, b"nop"));
    assert!(sys.lookup_path("class/net").is_some());
    assert!(sys.lookup_path("kernel/osrelease").is_some());
    assert!(trace.lookup_path("current_tracer").is_some());
    assert!(sys.lookup_path("current_tracer").is_none());
    assert!(trace.lookup_path("class/net").is_none());
    assert_ne!(sys.as_inode().fsid(), trace.as_inode().fsid());
}

#[test]
fn pseudofs_root_ino_is_fixed_and_target_independent() {
    use vfs::fs::FileSystem;

    let a = PseudoFs::new("bpf", 0xcafe_4a11);
    let b = PseudoFs::new("bpf", 0xcafe_4a11);
    assert_eq!(a.root().unwrap().ino(), PSEUDO_ROOT_INO);
    assert_eq!(b.root().unwrap().ino(), PSEUDO_ROOT_INO);
    assert_eq!(PSEUDO_ROOT_INO, 1);
    assert_eq!(a.root().unwrap().ino(), b.root().unwrap().ino());
    a.root_dir().ensure_dir_path("sub");
    let child = a.root_dir().lookup_path("sub").expect("child dir");
    assert_ne!(child.ino(), PSEUDO_ROOT_INO);
    assert_eq!(child.ino(), dir_ino("/sub"));
}

#[test]
fn remove_subtree_drops_branch() {
    let r = root();
    r.insert_path("/dev/pts/0", PseudoSymlink::new(8, 0, b"0"));
    assert_eq!(r.remove_subtree("/dev/pts"), 1);
    assert!(r.lookup_path("/dev/pts").is_none());
    assert_eq!(r.remove_subtree("/dev/pts"), 0);
}

#[test]
fn dir_inode_routed_through_icache_dedup() {
    use vfs::fs::FileSystem;

    let fs = PseudoFs::new("kernfs", 0x1234);
    let root_inode = fs.root().expect("root inode");
    let sb = test_sb(&fs, root_inode);

    fs.root_dir().ensure_dir_path("sub");
    let sub_ino = dir_ino("/sub");
    let a = fs.root_dir().lookup_path("sub").expect("sub dir");
    assert_eq!(a.ino(), sub_ino);
    let b = fs.root_dir().lookup_path("sub").expect("sub dir again");
    assert!(Arc::ptr_eq(&a, &b));

    let via_lookup = sb.ilookup(sub_ino).expect("dir cached in icache");
    assert!(Arc::ptr_eq(&a, &via_lookup));
    let via_iget = sb.iget(sub_ino, || panic!("iget must hit the cache, not rebuild"));
    assert!(Arc::ptr_eq(&a, &via_iget));
}

#[test]
fn leaf_inode_routed_through_icache_dedup() {
    use vfs::fs::FileSystem;

    let fs = PseudoFs::new("kernfs", 0x1234);
    let root_inode = fs.root().expect("root inode");
    let sb = test_sb(&fs, root_inode);

    let leaf_ino: Ino = 0x7000_0042;
    fs.root_dir().insert_path("dir/leaf", PseudoSymlink::new(leaf_ino, fs.magic(), b"/tgt"));

    let a = fs.root_dir().lookup_path("dir/leaf").expect("leaf");
    assert_eq!(a.ino(), leaf_ino);
    assert_eq!(a.file_type(), FileType::Symlink);
    let b = fs.root_dir().lookup_path("dir/leaf").expect("leaf again");
    assert!(Arc::ptr_eq(&a, &b));

    let dir = fs.root_dir().lookup_path("dir").expect("dir");
    let via_lookup = dir.lookup("leaf").expect("leaf via op_lookup");
    assert!(Arc::ptr_eq(&a, &via_lookup));

    let via_ilookup = sb.ilookup(leaf_ino).expect("leaf cached in icache");
    assert!(Arc::ptr_eq(&a, &via_ilookup));
    let via_iget = sb.iget(leaf_ino, || panic!("iget must hit the cache, not rebuild"));
    assert!(Arc::ptr_eq(&a, &via_iget));
}
