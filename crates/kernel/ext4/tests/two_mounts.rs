//! Stage-3 de-singletonisation gate: two independent `Ext4Mount`
//! instances over two DIFFERENT fixture images must not see each other's
//! inodes. Before Stage 3 every lookup funnelled through one global
//! `MOUNT_PTR`, so a second mount would have aliased the first; this
//! test proves each `Ext4Mount` reads only its own device.
//!
//! Mount A = mini.img  (root dir holds `hello.txt`; no `/etc`, no `/usr`)
//! Mount B = walk.img   (root dir holds `/etc/sub/deep.txt`,
//!                       `/usr/bin/realtool`, symlinks; no `hello.txt`)

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;

const MINI: &[u8] = include_bytes!("mini.img");
const WALK: &[u8] = include_bytes!("walk.img");
const BLOCK_SIZE: u32 = 512;

fn disk(image: &[u8]) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (BLOCK_SIZE as u64);
    let d: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image.to_vec() };
    d.submit_sync(&mut req).expect("memdisk write");
    d
}

fn open(image: &[u8]) -> Arc<ext4::rootfs::Ext4Mount> {
    ext4::rootfs::Ext4Mount::open(disk(image)).expect("Ext4Mount::open")
}

/// Each mount resolves ONLY its own contents; the other's unique paths ENOENT.
#[test]
fn no_cross_mount_path_visibility() {
    let a = open(MINI); // has hello.txt
    let b = open(WALK); // has /etc/sub/deep.txt, /usr/bin/realtool

    // A sees its own file, B does not.
    assert!(a.state().lookup_path(b"/hello.txt").is_some(), "A must see its own hello.txt");
    assert!(b.state().lookup_path(b"/hello.txt").is_none(),  "B must NOT see A's hello.txt");

    // B sees its own paths, A does not.
    assert!(b.state().lookup_path(b"/etc/sub/deep.txt").is_some(), "B must see deep.txt");
    assert!(a.state().lookup_path(b"/etc/sub/deep.txt").is_none(),  "A must NOT see B's deep.txt");
    assert!(b.state().lookup_path(b"/usr/bin/realtool").is_some(),  "B must see realtool");
    assert!(a.state().lookup_path(b"/usr/bin/realtool").is_none(),  "A must NOT see B's realtool");
}

/// Same inode NUMBER in both mounts must map to different on-disk inodes:
/// a read via mount A never returns mount B's bytes. inode 2 = root dir on
/// both; reading root-dir entries must come from each mount's own device.
#[test]
fn same_ino_distinct_inodes() {
    let a = open(MINI);
    let b = open(WALK);

    // Root dir entry sets differ. Collect each mount's top-level names.
    let mut a_names = alloc::vec::Vec::new();
    a.state().read_dir(b"/", |n, _| a_names.push(n.to_vec())).expect("A readdir /");
    let mut b_names = alloc::vec::Vec::new();
    b.state().read_dir(b"/", |n, _| b_names.push(n.to_vec())).expect("B readdir /");

    assert!(a_names.iter().any(|n| n == b"hello.txt"), "A root has hello.txt");
    assert!(!a_names.iter().any(|n| n == b"etc"), "A root has no etc");
    assert!(b_names.iter().any(|n| n == b"etc"), "B root has etc");
    assert!(!b_names.iter().any(|n| n == b"hello.txt"), "B root lacks hello.txt");
}

/// Per-mount page caches are independent: caching a file in A leaves B's
/// cache stats untouched (no shared global cache aliasing inode numbers).
#[test]
fn page_caches_are_per_mount() {
    let a = open(MINI);
    let b = open(WALK);

    let (b_h0, b_m0) = b.state().cache_stats();
    let _ = a.state().read_file(b"/hello.txt").expect("read A/hello.txt");
    let (b_h1, b_m1) = b.state().cache_stats();
    assert_eq!((b_h0, b_m0), (b_h1, b_m1), "reading A must not touch B's cache counters");

    let (a_h0, _) = a.state().cache_stats();
    let _ = a.state().read_file(b"/hello.txt"); // second read → cache hit on A
    let (a_h1, _) = a.state().cache_stats();
    assert!(a_h1 > a_h0, "A's own cache records the hit");
}

/// FileSystem trait surface routes through each instance's own mount.
#[test]
fn fs_trait_routes_per_instance() {
    let a: Arc<dyn FileSystem> = open(MINI);
    let b: Arc<dyn FileSystem> = open(WALK);
    assert!(a.lookup("/hello.txt").is_some());
    assert!(a.lookup("/usr/bin/realtool").is_none());
    assert!(b.lookup("/usr/bin/realtool").is_some());
    assert!(b.lookup("/hello.txt").is_none());
    assert!(a.root().is_some() && b.root().is_some());
}

/// Bug #2: the VFS ino marker is high-32, leaving a FULL 32-bit ext4 ino.
/// wrap → detect → unwrap must round-trip every ino (incl. ≥ 65536 and
/// the max 32-bit ino), and a non-ext4 ino must NOT be misdetected.
#[test]
fn ino_marker_roundtrip_full_32bit() {
    use ext4::rootfs::{ext4_wrap_ino, is_ext4_ino, ext4_unwrap_ino,
        EXT4_INO_MARK, EXT4_INO_MASK};
    for ino in [2u32, 11, 0xFFFF, 0x1_0000, 0x10_0000, 0xFFFF_FFFF] {
        let v = ext4_wrap_ino(ino);
        assert!(is_ext4_ino(v), "marker must be detected for ino {ino:#x}");
        assert_eq!(ext4_unwrap_ino(v), ino, "ino {ino:#x} must round-trip");
    }
    // Marker geometry: high-32 mark, full low-32 ino space.
    assert_eq!(EXT4_INO_MARK, 0x6E54_0000_0000_0000);
    assert_eq!(EXT4_INO_MASK, 0xFFFF_FFFF_0000_0000);
    assert_eq!(ext4_unwrap_ino(EXT4_INO_MARK | 0xFFFF_FFFF), 0xFFFF_FFFF);
    // A bare (unmarked) ino must not be mistaken for ext4.
    assert!(!is_ext4_ino(0x12u64));
    assert!(!is_ext4_ino(0xFFFF_FFFFu64));
    // Other subsystems' high-32 tags must not collide with the marker.
    for other in [0x534F_434B_0000_0000u64, 0x5045_5246_0000_0000,
                  0x5546_4644_0000_0000, 0x4E4C_534B_0000_0000,
                  0x494F_5552_0000_0000, 0x4C4E_4400_0000_0000] {
        assert!(!is_ext4_ino(other), "tag {other:#x} must not look like ext4");
    }
}

/// Bug #1: freeing an O_TMPFILE orphan on mount B must route through B's
/// OWN state and never touch mount A's same-numbered on-disk inode.
/// Before the fix the close-hook hard-resolved root() and freed against
/// the root mount, so closing a non-root orphan at on-disk ino N would
/// silently free the root's inode N. Here we drive the same routing the
/// hook uses (per-mount `RootfsState`) and assert A is undisturbed.
#[test]
fn orphan_free_isolated_to_owning_mount() {
    let a = open(MINI);
    let b = open(WALK);

    // Allocate an O_TMPFILE orphan in B's /  (root dir = inode 2).
    let orphan = b.state()
        .create_anonymous_at(b"/", 0o600)
        .expect("B create O_TMPFILE orphan");
    // The wrapped ino carries the ext4 marker and a real low-32 ino.
    let v = orphan.ino();
    assert!(ext4::rootfs::is_ext4_ino(v), "orphan ino must be ext4-marked");
    let n = ext4::rootfs::ext4_unwrap_ino(v);
    assert!(b.state().orphan_contains(n), "B tracks the orphan");

    // Snapshot A's inode at the SAME on-disk number (it exists on A's
    // device, with its own links_count). It must survive B's free.
    let a_before = a.state().mount.read_inode(n)
        .expect("A has an inode at the colliding number");

    // Free the orphan against B's owning state (what close_hook does via
    // the wrapper's `st`). Must NOT call root() / mount A.
    b.state().free_orphan_inode(n).expect("free B's orphan");
    b.state().orphan_remove(n);

    // A's inode at N is byte-for-byte intact: no cross-mount corruption.
    let a_after = a.state().mount.read_inode(n)
        .expect("A's inode at N still readable after B's free");
    assert_eq!(a_before.links_count, a_after.links_count,
        "B's orphan free must not alter A's inode links_count");
    assert_eq!(a_before.size, a_after.size,
        "B's orphan free must not alter A's inode size");
    assert_eq!(a_before.mode, a_after.mode,
        "B's orphan free must not alter A's inode mode");
    // A's own root dir still resolves its real contents.
    assert!(a.state().lookup_path(b"/hello.txt").is_some(),
        "A's tree intact after B orphan free");
}
