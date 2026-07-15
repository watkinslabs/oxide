//! Mount namespace identity and lifetime are owned by `Arc<MntNamespace>`.
//! The numeric registry is a weak live index, except for the initial namespace
//! pin, and numeric mount-table state operations cannot recreate a dead owner.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static CURRENT_NS: AtomicU64 = AtomicU64::new(0);

fn current_ns() -> u64 { CURRENT_NS.load(Ordering::Acquire) }

struct TestFs { root_ino: u64 }

impl FileSystem for TestFs {
    fn name(&self) -> &str { "mntns-owner" }
    fn root(&self) -> Option<InodeRef> { Some(test_dir(self.root_ino)) }
}

struct TestDirOps;

impl vfs::InodeOps for TestDirOps {
    fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> {
        Ok(test_dir(0xB865))
    }
}

fn test_dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(TestDirOps), vfs::default_file_ops()).build()
}

fn test_fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TestFs { root_ino: ino }) }

#[test]
fn namespace_arc_is_the_lifetime_authority() {
    common::install();
    vfs::mount::set_current_ns_provider(current_ns);

    let init = vfs::mntns::initial();
    let init_again = vfs::mntns::initial();
    assert!(Arc::ptr_eq(&init, &init_again), "initial returns one canonical object");
    assert_eq!(init.id(), 0);
    assert_eq!(init.owner_user_namespace().id().as_u64(), 0);
    drop(init_again);
    drop(init);
    assert!(vfs::mntns::ns_by_id(0).is_some(), "registry's init pin is immortal");

    let owner = namespace_identity::allocate(namespace_identity::NamespaceKind::User,
        namespace_identity::initial(namespace_identity::NamespaceKind::User), None)
        .expect("allocate user owner");
    let namespace = vfs::mntns::allocate(Arc::clone(&owner)).expect("allocate mount namespace");
    let id = namespace.id();
    assert!(Arc::ptr_eq(&namespace.owner_user_namespace(), &owner));
    assert_eq!(Arc::strong_count(&namespace), 1, "non-init registry owns only Weak");
    assert!(Arc::ptr_eq(&namespace, &vfs::mntns::ns_by_id(id).unwrap()));

    CURRENT_NS.store(id, Ordering::Release);
    common::register("/", test_fs(1)).expect("mount namespace root");
    common::register("/child", test_fs(2)).expect("mount child tree");
    let survivor = Arc::clone(&namespace);
    drop(namespace);
    assert!(vfs::mntns::ns_by_id(id).is_some(), "cloned owner keeps index live");
    assert_eq!(vfs::mount::snapshot_ns_view(id).len(), 2, "cloned owner keeps mount tree live");

    let generation = vfs::mntns::mount_generation();
    drop(survivor);
    assert!(vfs::mntns::ns_by_id(id).is_none(), "final drop removes weak index entry");
    assert!(vfs::mount::snapshot_ns_view(id).is_empty(), "final drop reaps mount tree");
    assert_eq!(vfs::mntns::mount_generation(), generation + 1, "tree is reaped once");

    vfs::mntns::ns_set_root(id, 99);
    vfs::mntns::bump_gen(id);
    assert_eq!(vfs::mntns::count_mounts(id, 1), Err(VfsError::Enoent));
    assert!(vfs::mntns::ns_by_id(id).is_none(), "numeric state cannot resurrect dead ID");
    let replacement = vfs::mntns::allocate(Arc::clone(&owner)).expect("allocate after final drop");
    assert!(replacement.id() > id, "namespace IDs are never reused");
    drop(replacement);

    let raced = vfs::mntns::allocate(owner).expect("allocate raced namespace");
    let raced_id = raced.id();
    let pinned_barrier = Arc::new(Barrier::new(2));
    let release_barrier = Arc::new(Barrier::new(2));
    let peer_pinned = Arc::clone(&pinned_barrier);
    let peer_release = Arc::clone(&release_barrier);
    let lookup = std::thread::spawn(move || {
        let pinned = vfs::mntns::ns_by_id(raced_id).expect("lookup wins live-owner race");
        peer_pinned.wait();
        peer_release.wait();
        drop(pinned);
    });
    pinned_barrier.wait();
    drop(raced);
    assert!(vfs::mntns::ns_by_id(raced_id).is_some(), "concurrent lookup pins owner");
    release_barrier.wait();
    lookup.join().unwrap();
    assert!(vfs::mntns::ns_by_id(raced_id).is_none(), "last raced pin performs final drop");
}
