//! `file->f_version` directory-iteration change detector (Linux `struct file`
//! `f_version`, compared against `inode->i_version` by every `iterate_shared`
//! to drop a stale `readdir` cursor). Before this the `File` carried no
//! `f_version` slot at all, so a directory reader could not tell whether the
//! directory had been mutated under its cached position. This proves the slot
//! defaults to 0, round-trips through `set_f_version`, and that
//! `dir_version_changed` tracks the inode's live change-version: equal right
//! after a stamp, true once the inode bumps, false again after a re-stamp, and
//! inert on an inode that opts out of a version counter (the trait default).

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use vfs::inode::{inode_inc_iversion, inode_query_iversion, Inode};
use vfs::{Dentry, File, FileType, InodeRef, KResult, OpenFlags, VfsError};

/// Directory inode that opts into a change counter (Linux `SB_I_VERSION`).
struct VDir { ver: AtomicU64 }
impl Inode for VDir {
    fn ino(&self) -> vfs::Ino { 0xD1 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
    fn i_version_raw(&self) -> Option<&AtomicU64> { Some(&self.ver) }
}

/// Directory inode with no version counter (the trait default).
struct PlainDir;
impl Inode for PlainDir {
    fn ino(&self) -> vfs::Ino { 0xD2 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

fn open_dir(inode: InodeRef) -> Arc<File> {
    let d = Dentry::new(None, "d".into(), Arc::clone(&inode));
    File::new(inode, d, OpenFlags::O_DIRECTORY)
}

/// A freshly opened `File` has `f_version == 0` (unstamped), and `set_f_version`
/// stores the value a `readdir` cursor was built against verbatim.
#[test]
fn f_version_defaults_zero_and_round_trips() {
    let f = open_dir(Arc::new(VDir { ver: AtomicU64::new(0) }) as InodeRef);
    assert_eq!(f.f_version(), 0, "unstamped f_version is 0");
    f.set_f_version(7);
    assert_eq!(f.f_version(), 7, "set_f_version round-trips the stamp");
}

/// Stamp from the inode's current change-version, then the detector reports
/// "unchanged"; after the directory's `i_version` is bumped it reports
/// "changed"; re-stamping clears it again.
#[test]
fn dir_version_changed_tracks_inode_iversion() {
    let ino = Arc::new(VDir { ver: AtomicU64::new(0) });
    let f = open_dir(Arc::clone(&ino) as InodeRef);

    // Stamp the cursor against the live version. `inode_query_iversion` reports
    // the real version (and latches the QUERIED flag) without advancing it.
    f.set_f_version(inode_query_iversion(&*ino));
    assert!(!f.dir_version_changed(), "no mutation since the stamp ⇒ unchanged");

    // Mutate the directory: a forced bump advances the real change-version.
    inode_inc_iversion(&*ino);
    assert!(f.dir_version_changed(), "i_version advanced past the stamp ⇒ stale cursor");

    // Re-establish the cursor at the new version: unchanged again.
    f.set_f_version(inode_query_iversion(&*ino));
    assert!(!f.dir_version_changed(), "re-stamp clears the staleness");

    // A second mutation flips it once more.
    inode_inc_iversion(&*ino);
    assert!(f.dir_version_changed(), "subsequent mutation is detected again");
}

/// An inode that tracks no version counter (`i_version_raw == None`) always
/// reports version 0, so a stamped `File` never sees a change — the detector is
/// inert rather than spuriously firing.
#[test]
fn no_iversion_counter_never_changes() {
    let ino = Arc::new(PlainDir);
    let f = open_dir(Arc::clone(&ino) as InodeRef);
    f.set_f_version(inode_query_iversion(&*ino));
    assert!(!f.dir_version_changed(), "counter-less inode ⇒ never stale");
    inode_inc_iversion(&*ino); // no-op on a counter-less inode
    assert!(!f.dir_version_changed(), "still inert after a no-op bump");
}
