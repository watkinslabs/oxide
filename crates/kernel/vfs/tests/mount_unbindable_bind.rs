//! B252 [D15 regression]: MS_UNBINDABLE edges in recursive bind
//! (`bind_submounts_rec`, Linux `copy_tree` `IS_MNT_UNBINDABLE` → -EINVAL).
//! The unbindable-honored behavior is already implemented on F649 but had no
//! dedicated regression test; this pins it: an unbindable SUBMOUNT is skipped
//! by an rbind, and an unbindable SOURCE root yields zero mirrors. Exercises the
//! real global mount engine via the hosted dentry-identity fixture. Serializes
//! on `SERIAL`.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::Propagation;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0xB00B);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir { ino: self.root_ino })) }
}
struct TDir { ino: u64 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

fn mounted(p: &str) -> bool { common::mount_at_path_exact(p).is_some() }

// An rbind of a subtree mirrors its bindable submounts but SKIPS an unbindable
// one (Linux `copy_tree` drops `IS_MNT_UNBINDABLE` children).
#[test]
fn rbind_skips_unbindable_submount() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/src", fs(0xA)).expect("src");
    common::register("/src/keep", fs(0xA1)).expect("keep");
    common::register("/src/skip", fs(0xA2)).expect("skip");
    common::set_propagation("/src/skip", Propagation::Unbindable).expect("unbindable");

    let n = common::bind_submounts_rec("/src", "/dst");
    assert_eq!(n, 1, "only the bindable submount is mirrored");
    assert!(mounted("/dst/keep"), "bindable submount mirrored");
    assert!(!mounted("/dst/skip"), "unbindable submount NOT mirrored");
}

// An rbind whose SOURCE root is unbindable produces no mirrors at all.
#[test]
fn rbind_of_unbindable_source_is_empty() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/usrc", fs(0xA)).expect("usrc");
    common::register("/usrc/child", fs(0xC)).expect("child");
    common::set_propagation("/usrc", Propagation::Unbindable).expect("unbindable src");

    let n = common::bind_submounts_rec("/usrc", "/udst");
    assert_eq!(n, 0, "unbindable source yields zero mirrors");
    assert!(!mounted("/udst/child"), "nothing mirrored under the target");
}
