//! superblock-D6: `sget`/`fs_supers` superblock dedup. `sget(dev, build)`
//! returns an EXISTING registered instance for the same backing device (taking
//! one `s_active` + `s_count` reference) instead of building a duplicate, and
//! `fs_supers` lists the live registry. Distinct devices get distinct instances.
//! (Wiring mount.rs `register`/`register_bind` to call `sget` is cross-lane.)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vfs::superblock::{fs_supers, sget, FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{KResult, VfsError};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "tsgetfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn build(dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0x5167, dev, 4096, "tsgetfs".into(), Arc::new(()))
}

/// A second `sget` for the same dev SHARES the instance: same `Arc`, the build
/// closure is not re-run, and the active/existence refcounts are bumped.
#[test]
fn sget_shares_existing_instance() {
    let dev = 0x1000_0001;
    let builds = Arc::new(AtomicUsize::new(0));

    let b1 = builds.clone();
    let a = sget(dev, || { b1.fetch_add(1, Ordering::SeqCst); build(dev) });
    assert_eq!(builds.load(Ordering::SeqCst), 1, "first sget built the instance");
    let active_after_first = a.s_active();
    let count_after_first = a.s_count();

    let b2 = builds.clone();
    let b = sget(dev, || { b2.fetch_add(1, Ordering::SeqCst); build(dev) });
    assert_eq!(builds.load(Ordering::SeqCst), 1, "second sget reused, did not build");
    assert!(Arc::ptr_eq(&a, &b), "same dev → same superblock instance");
    assert_eq!(b.s_active(), active_after_first + 1, "sget hit grabbed one s_active");
    assert_eq!(b.s_count(), count_after_first + 1, "sget hit bumped s_count");
}

/// Distinct backing devices get distinct instances; both appear in `fs_supers`.
#[test]
fn sget_distinct_dev_distinct_instance() {
    let d1 = 0x2000_0001;
    let d2 = 0x2000_0002;
    let a = sget(d1, || build(d1));
    let c = sget(d2, || build(d2));
    assert!(!Arc::ptr_eq(&a, &c), "different dev → different instance");

    let supers = fs_supers();
    assert!(supers.iter().any(|s| Arc::ptr_eq(s, &a)), "fs_supers lists instance a");
    assert!(supers.iter().any(|s| Arc::ptr_eq(s, &c)), "fs_supers lists instance c");
}
