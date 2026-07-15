//! Mount namespace identity and lifetime are owned by `Arc<MntNamespace>`.
//! The numeric registry is a weak live index, except for the initial namespace
//! pin, and numeric mount-table state operations cannot recreate a dead owner.

use std::sync::{Arc, Barrier, Mutex};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static CURRENT_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);
static SERIAL: Mutex<()> = Mutex::new(());

fn current_ns() -> vfs::mntns::MntNamespaceRef {
    CURRENT_NS.lock().unwrap().as_ref().cloned().unwrap_or_else(vfs::mntns::initial)
}

fn set_current(namespace: Option<vfs::mntns::MntNamespaceRef>) {
    *CURRENT_NS.lock().unwrap() = namespace;
}

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
    let _serial = SERIAL.lock().unwrap();
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

    set_current(Some(Arc::clone(&namespace)));
    common::register("/", test_fs(1)).expect("mount namespace root");
    common::register("/child", test_fs(2)).expect("mount child tree");
    let survivor = Arc::clone(&namespace);
    drop(namespace);
    assert!(vfs::mntns::ns_by_id(id).is_some(), "cloned owner keeps index live");
    assert_eq!(vfs::mount::snapshot_ns_view(id).len(), 2, "cloned owner keeps mount tree live");

    let generation = vfs::mntns::mount_generation();
    set_current(None);
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

#[test]
fn final_drop_waits_for_graft_reservation_abort() {
    let _serial = SERIAL.lock().unwrap();
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).unwrap();
    let id = namespace.id();
    let reservation = vfs::mntns::MountReservation::reserve(&namespace, 1).unwrap();

    drop(namespace);
    assert!(vfs::mntns::ns_by_id(id).is_some(), "reservation pins exact owner");
    assert_eq!(vfs::mntns::ns_pending_mounts(id), 1, "reservation remains charged");

    drop(reservation);
    assert!(vfs::mntns::ns_by_id(id).is_none(), "abort releases final owner");
    assert!(vfs::mount::snapshot_ns_view(id).is_empty(), "dead namespace cannot retain state");
}

#[test]
fn final_drop_waits_for_namespace_copy_transaction() {
    let _serial = SERIAL.lock().unwrap();
    common::install();
    vfs::mount::set_current_ns_provider(current_ns);
    let init = vfs::mntns::initial();
    let source = vfs::mntns::allocate(init.owner_user_namespace()).unwrap();
    let destination = vfs::mntns::allocate(init.owner_user_namespace()).unwrap();
    let (source_id, destination_id) = (source.id(), destination.id());
    set_current(Some(Arc::clone(&source)));
    common::register("/", test_fs(11)).unwrap();
    set_current(None);

    let pinned = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let inspect = Arc::new(Barrier::new(2));
    let peer_pinned = Arc::clone(&pinned);
    let peer_release = Arc::clone(&release);
    let peer_inspect = Arc::clone(&inspect);
    let copy = std::thread::spawn(move || {
        peer_pinned.wait();
        peer_release.wait();
        vfs::mount::copy_mnt_ns(&source, &destination).unwrap();
        assert!(!vfs::mount::snapshot_ns_view(destination_id).is_empty());
        peer_inspect.wait();
    });

    pinned.wait();
    assert!(vfs::mntns::ns_by_id(source_id).is_some());
    assert!(vfs::mntns::ns_by_id(destination_id).is_some());
    release.wait();
    inspect.wait();
    copy.join().unwrap();

    assert!(vfs::mntns::ns_by_id(source_id).is_none(), "source finalizes after copy pin drops");
    assert!(vfs::mntns::ns_by_id(destination_id).is_none(), "destination finalizes after copy pin drops");
    assert!(vfs::mount::snapshot_ns_view(destination_id).is_empty(), "copy cannot republish dead state");
}
