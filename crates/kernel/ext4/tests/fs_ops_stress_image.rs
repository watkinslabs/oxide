//! Comprehensive ext4 filesystem-op stress harness — the "does mkdir/symlink/
//! create/nested/dir-growth actually work the Linux way" test the boot needs so
//! backend bugs surface HOSTED (real MountError) instead of one-boot-at-a-time
//! as a swallowed `VfsError::Eio` (see rootfs/inode/special.rs mkdir/create,
//! which map every create_dir/create_file error to EIO). Reproduces the boot's
//! journald/udev failures: `mkdir /var/log/journal/<machine-id> err=5` and
//! `mkdir /run/udev err=5`.
//!
//! Backend = the REAL ext4 Mount over mini-j.img (journaled), driven through the
//! low-level create_dir/create_file/create_symlink/dir_link API that returns the
//! true MountError.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const ROOT: u32 = 2;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// mkdir a chain of components under `start`, returning the leaf ino. Surfaces
/// the true MountError at the failing component (what the boot hides as EIO).
fn mkdir_p(m: &ext4::Mount, start: u32, comps: &[&str]) -> u32 {
    let mut cur = start;
    for c in comps {
        cur = m.create_dir(cur, c.as_bytes(), 0o755, 0, 0)
            .unwrap_or_else(|e| panic!("create_dir {c:?} under ino {cur}: {e:?}"));
    }
    cur
}

/// The exact boot failure: journald's `/var/log/journal/<machine-id>`. journald
/// creates the persistent journal dir tree; every level must succeed.
#[test]
fn journald_var_log_journal_machine_id_dir_chain() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    // /var and /var/log may or may not pre-exist in the image; create each
    // component, resolving via full-path lookup if it already exists.
    let mut cur = ROOT;
    let mut path = alloc::string::String::new();
    for c in ["var", "log", "journal"] {
        path.push('/'); path.push_str(c);
        cur = match m.create_dir(cur, c.as_bytes(), 0o755, 0, 0) {
            Ok(ino) => ino,
            Err(_) => m.lookup_path(path.as_bytes())
                .unwrap_or_else(|e| panic!("component {path:?} neither created nor found: {e:?}")),
        };
    }
    let mid = "fa52435e5fe94e5cbb8bff1a050ba889";
    let leaf = m.create_dir(cur, mid.as_bytes(), 0o755, 0, 0)
        .unwrap_or_else(|e| panic!("mkdir /var/log/journal/{mid} (the boot EIO): {e:?}"));
    // The leaf must be found again by full-path lookup (dir_link persisted it).
    let found = m.lookup_path(alloc::format!("/var/log/journal/{mid}").as_bytes())
        .unwrap_or_else(|e| panic!("lookup of freshly-created journal dir: {e:?}"));
    assert_eq!(found, leaf, "journal machine-id dir resolves to the created inode");
}

/// Directory-block GROWTH: create enough entries in one dir that the parent
/// directory's single block fills and `dir_link` must allocate + append a new
/// block (and, past a threshold, grow the extent tree). This is the classic
/// mkdir-EIO path (create_dir -> dir_link -> append_block/extent grow).
#[test]
fn dir_grows_past_one_block_of_entries() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let base = mkdir_p(&m, ROOT, &["bigdir"]);
    // Files (not dirs) to avoid exhausting the tiny 2 MiB image's dir-inode
    // budget; enough short entries (~130) to fill one 4 KiB dir block and force
    // `dir_link` to allocate + append a SECOND block — the classic mkdir-EIO
    // (create -> dir_link -> append_block/extent-grow) path.
    const N: usize = 130;
    for i in 0..N {
        let name = alloc::format!("entry_{i:04}");
        m.create_file(base, name.as_bytes(), 0o644, 0, 0)
            .unwrap_or_else(|e| panic!("create_file entry #{i} (dir-block growth): {e:?}"));
    }
    // Every entry must still resolve — no lost/overwritten dirents across blocks.
    for i in 0..N {
        let name = alloc::format!("/bigdir/entry_{i:04}");
        m.lookup_path(name.as_bytes())
            .unwrap_or_else(|e| panic!("lookup entry #{i} after growth: {e:?}"));
    }
}

/// Symlink create + resolve (create_symlink fast + slow path), and a regular
/// file create + the dir entry lands. Models udev rule / journald symlinks.
#[test]
fn symlink_and_file_create_resolve() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let d = mkdir_p(&m, ROOT, &["linkdir"]);
    // A real target so the FOLLOWING lookup_path resolves through the symlink.
    let tgt = m.create_dir(d, b"tgt", 0o755, 0, 0).unwrap_or_else(|e| panic!("mkdir tgt: {e:?}"));
    // Fast symlink (<=60B target stored inline), pointing at the real target.
    m.create_symlink(d, b"short", b"/linkdir/tgt", 0, 0)
        .unwrap_or_else(|e| panic!("create_symlink short: {e:?}"));
    assert_eq!(m.lookup_path(b"/linkdir/short").unwrap(), tgt,
        "following /linkdir/short lands on the real target dir");
    // Slow symlink (>60B target => external data block). Exercises the slow
    // create_symlink path; creation must succeed (following is covered above).
    let long_target = alloc::format!("/some/deep/{}/target", "seg/".repeat(15));
    assert!(long_target.len() > 60);
    m.create_symlink(d, b"long", long_target.as_bytes(), 0, 0)
        .unwrap_or_else(|e| panic!("create_symlink long (slow path): {e:?}"));
    // Regular file.
    let f = m.create_file(d, b"file", 0o644, 0, 0)
        .unwrap_or_else(|e| panic!("create_file: {e:?}"));
    assert_eq!(m.lookup_path(b"/linkdir/file").unwrap(), f);
}

/// Everything created above must PERSIST across a remount (journal replay /
/// on-disk correctness), the way journald's persistent journal must survive.
#[test]
fn created_tree_persists_across_remount() {
    let disk = build_disk();
    let (top, leaf) = {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let top = m.create_dir(ROOT, b"persist", 0o755, 0, 0).unwrap_or_else(|e| panic!("mkdir /persist: {e:?}"));
        // Sanity: it's visible in the SAME mount instance before remount.
        assert_eq!(m.lookup_path(b"/persist").unwrap(), top, "created dir visible in same mount");
        let leaf = mkdir_p(&m, top, &["deep", "nested"]);
        (top, leaf)
    };
    // Reopen from the SAME MemDisk — the commit_metadata writes must be on disk.
    let m2 = ext4::Mount::open(disk).unwrap();
    assert_eq!(m2.lookup_path(b"/persist").unwrap(), top, "/persist persisted across remount");
    assert_eq!(m2.lookup_path(b"/persist/deep/nested").unwrap(), leaf, "nested dir persisted");
}

// Silence unused-import warning if a helper path is dropped later.
#[allow(dead_code)]
fn _touch(_: Vec<u8>) {}
