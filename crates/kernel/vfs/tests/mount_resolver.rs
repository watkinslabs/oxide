//! K2V V5: the unified mount-crossing resolver. `mount_root_at(abs)`
//! returns the root inode of whatever filesystem is mounted exactly at
//! `abs` — what `path_lookup` switches to when it crosses into a mount.
//! Verifies it over a synthetic FileSystem registered in the real mount
//! table, no QEMU.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct TDir { ino: u64 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

struct TestFs { root_ino: u64 }
impl FileSystem for TestFs {
    fn name(&self) -> &str { "testfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir { ino: self.root_ino })) }
    fn lookup(&self, _path: &str) -> Option<InodeRef> { None }
}

#[test]
fn resolver_returns_mount_root() {
    let fs = Arc::new(TestFs { root_ino: 0x1234 });
    vfs::mount::register("/x", fs).expect("register");
    let r = vfs::mount::mount_root_at("/x").expect("cross into /x");
    assert_eq!(r.ino(), 0x1234, "crossing returns the mounted fs root");
    assert_eq!(r.file_type(), FileType::Directory);
}

#[test]
fn resolver_skips_root_and_missing() {
    // `/` is the walk start — never a crossing target.
    assert!(vfs::mount::mount_root_at("/").is_none());
    // Nothing mounted at /nope.
    assert!(vfs::mount::mount_root_at("/nope-xyz").is_none());
}

// A fallback fs that exposes no root() but resolves the mountpoint via
// whole-path lookup — mount_root_at must still return its root (the
// tmpfs/proc/sys shape during the transition).
struct LookupOnlyFs;
impl FileSystem for LookupOnlyFs {
    fn name(&self) -> &str { "lookuponly" }
    fn lookup(&self, path: &str) -> Option<InodeRef> {
        if path == "/y" { Some(Arc::new(TDir { ino: 0x5678 })) } else { None }
    }
}

#[test]
fn resolver_falls_back_to_whole_path_lookup() {
    vfs::mount::register("/y", Arc::new(LookupOnlyFs)).expect("register");
    let r = vfs::mount::mount_root_at("/y").expect("cross into /y via lookup");
    assert_eq!(r.ino(), 0x5678);
}

// K2V V7: MS_MOVE relocates a mount's mount_point in place, preserving
// mnt_id + propagation; the new parent_id falls out of the prefix
// recompute. Verified over the real mount table, no QEMU.
#[test]
fn move_mount_relocates_preserving_mnt_id() {
    vfs::mount::register("/mv-src", Arc::new(TestFs { root_ino: 0xABCD })).expect("register");
    // Capture the mnt_id assigned at register time.
    let before = vfs::mount::snapshot();
    let id = before.iter().find(|m| m.mount_point == "/mv-src").expect("present").mnt_id;
    // Move it.
    vfs::mount::move_mount("/mv-src", "/mv-dst").expect("move");
    // Old point is gone, new point resolves to the same fs root + mnt_id.
    assert!(vfs::mount::mount_root_at("/mv-src").is_none(), "old point cleared");
    let r = vfs::mount::mount_root_at("/mv-dst").expect("cross into new point");
    assert_eq!(r.ino(), 0xABCD, "same fs root after move");
    let after = vfs::mount::snapshot();
    let m = after.iter().find(|m| m.mount_point == "/mv-dst").expect("moved present");
    assert_eq!(m.mnt_id, id, "mnt_id stable across MS_MOVE");
    // Moving a non-existent mount → Einval; onto an occupied point → Ebusy.
    assert!(matches!(vfs::mount::move_mount("/nope-mv", "/x2"), Err(VfsError::Einval)));
    vfs::mount::register("/occupied", Arc::new(TestFs { root_ino: 1 })).expect("register2");
    assert!(matches!(vfs::mount::move_mount("/mv-dst", "/occupied"), Err(VfsError::Ebusy)));
}

// K2V V7-b: bind-as-clone. register_bind mounts an arbitrary source inode
// as the mount root; mount_root_at returns THAT inode (not fs.root()), so
// the dentry walk mirrors the source subtree via per-component lookup —
// no path rewrite. Verified over the real mount table, no QEMU.
struct BindChildDir;
impl Inode for BindChildDir {
    fn ino(&self) -> vfs::Ino { 0xB14D }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    // Source subtree: "kid" resolves to a known inode.
    fn lookup(&self, n: &str) -> KResult<InodeRef> {
        if n == "kid" { Ok(Arc::new(TDir { ino: 0xC0DE })) } else { Err(VfsError::Enoent) }
    }
}

#[test]
fn bind_as_clone_roots_at_source_inode() {
    let bindfs = Arc::new(TestFs { root_ino: 0x9999 }); // fs.root() must NOT win
    let src_root: InodeRef = Arc::new(BindChildDir);
    vfs::mount::register_bind("/bnd", bindfs, src_root).expect("register_bind");
    // Crossing into the bind returns the SOURCE inode, not fs.root().
    let r = vfs::mount::mount_root_at("/bnd").expect("cross into bind");
    assert_eq!(r.ino(), 0xB14D, "bind root is the source inode, not fs.root()");
    // And the walk mirrors the source subtree per-component.
    let kid = r.lookup("kid").expect("child via source subtree");
    assert_eq!(kid.ino(), 0xC0DE);
}

// K2V V7-c: MS_REC recursive bind clones every submount of src to the
// matching path under tgt as a bind-as-clone. Verified over the real
// mount table, no QEMU.
#[test]
fn ms_rec_clones_submounts() {
    // A source subtree with a nested mount: /rsrc and /rsrc/sub.
    vfs::mount::register("/rsrc", Arc::new(TestFs { root_ino: 0x100 })).expect("src");
    vfs::mount::register("/rsrc/sub", Arc::new(TestFs { root_ino: 0x200 })).expect("submount");
    // Bind the top src→tgt (as sys_mount does), then recurse.
    let r = vfs::mount::mount_root_at("/rsrc").expect("src root");
    vfs::mount::register_bind("/rtgt", Arc::new(TestFs { root_ino: 0xDEAD }), r).expect("bind top");
    let n = vfs::mount::bind_submounts_rec("/rsrc", "/rtgt");
    assert_eq!(n, 1, "one submount cloned");
    // The cloned submount resolves at the mirrored path with the source root.
    let sub = vfs::mount::mount_root_at("/rtgt/sub").expect("cloned submount present");
    assert_eq!(sub.ino(), 0x200, "cloned submount keeps the source fs root");
}

// K2V V7-d: propagation peer-group ids. MS_SHARED assigns a fresh
// peer_group (distinct from mnt_id); two shared mounts get distinct
// groups; MS_PRIVATE clears it. Verified over the real mount table.
#[test]
fn ms_shared_assigns_distinct_peer_groups() {
    use std::sync::atomic::Ordering;
    use vfs::mount::Propagation;
    vfs::mount::register("/pg-a", Arc::new(TestFs { root_ino: 1 })).expect("a");
    vfs::mount::register("/pg-b", Arc::new(TestFs { root_ino: 2 })).expect("b");
    vfs::mount::set_propagation("/pg-a", Propagation::Shared).expect("share a");
    vfs::mount::set_propagation("/pg-b", Propagation::Shared).expect("share b");
    let snap = vfs::mount::snapshot();
    let ga = snap.iter().find(|m| m.mount_point == "/pg-a").unwrap().peer_group.load(Ordering::Acquire);
    let gb = snap.iter().find(|m| m.mount_point == "/pg-b").unwrap().peer_group.load(Ordering::Acquire);
    assert!(ga != 0 && gb != 0, "shared mounts get a peer group");
    assert!(ga != gb, "distinct shared mounts get distinct peer groups");
    // Re-sharing is idempotent (keeps the same group).
    vfs::mount::set_propagation("/pg-a", Propagation::Shared).expect("reshare a");
    let ga2 = vfs::mount::snapshot().iter().find(|m| m.mount_point == "/pg-a").unwrap().peer_group.load(Ordering::Acquire);
    assert_eq!(ga, ga2, "re-MS_SHARED keeps the peer group");
    // MS_PRIVATE drops the group.
    vfs::mount::set_propagation("/pg-a", Propagation::Private).expect("priv a");
    let ga3 = vfs::mount::snapshot().iter().find(|m| m.mount_point == "/pg-a").unwrap().peer_group.load(Ordering::Acquire);
    assert_eq!(ga3, 0, "MS_PRIVATE clears the peer group");
}

// K2V V7/U2: mounts are stamped with the creating task's mount-ns via the
// installed provider. No provider ⇒ ns 0. Foundation for per-ns trees.
#[test]
fn register_stamps_mount_ns_from_provider() {
    // No provider installed yet for this key ⇒ ns 0.
    vfs::mount::register("/ns-default", Arc::new(TestFs { root_ino: 1 })).expect("a");
    let g0 = vfs::mount::snapshot();
    let m0 = g0.iter().find(|m| m.mount_point == "/ns-default").unwrap();
    assert_eq!(m0.ns, 0, "no provider ⇒ ns 0");
    // Install a provider that reports ns 42; the next mount is stamped 42.
    vfs::mount::set_current_ns_provider(|| 42);
    vfs::mount::register("/ns-42", Arc::new(TestFs { root_ino: 2 })).expect("b");
    let g1 = vfs::mount::snapshot();
    let m1 = g1.iter().find(|m| m.mount_point == "/ns-42").unwrap();
    assert_eq!(m1.ns, 42, "provider ns stamped onto the new mount");
    // Restore so other tests see ns 0.
    vfs::mount::set_current_ns_provider(|| 0);
}
