//! Lane 3 (ext4-compat-plan): the concurrent-create allocator race behind the
//! boot's `mkdir /var/log/journal/<id> err=5`. `try_alloc_inode_in_group` /
//! `try_alloc_in_group` read a group bitmap, `find_first_clear`, and set the bit
//! WITHOUT holding a lock across the read-modify-write, so two concurrent
//! allocations pick the SAME free bit -> double-allocate one inode/block ->
//! corruption -> EIO. Linux serializes with `ext4_lock_group`. This drives many
//! creates from multiple threads into distinct parent dirs and asserts every
//! allocated inode is unique + the fs stays consistent across a remount.

extern crate alloc;
use std::sync::{Arc, Mutex};

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

fn fresh_disk() -> Arc<MemDisk<TaskList>> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn concurrent_creates_never_double_allocate_an_inode() {
    let disk = fresh_disk();
    let m = Arc::new(ext4::Mount::open(disk.clone() as Arc<dyn BlockDevice>).unwrap());
    // Distinct parent dirs so per-parent i_rwsem serialization (in the real
    // kernel) does NOT hide the shared-allocator race.
    const THREADS: usize = 8;
    const PER: usize = 40;
    let parents: alloc::vec::Vec<u32> = (0..THREADS)
        .map(|i| m.create_dir(2, alloc::format!("p{i}").as_bytes(), 0o755, 0, 0).expect("parent"))
        .collect();
    let inos: Arc<Mutex<alloc::vec::Vec<u32>>> = Arc::new(Mutex::new(alloc::vec::Vec::new()));
    std::thread::scope(|s| {
        for (t, &p) in parents.iter().enumerate() {
            let m = m.clone();
            let inos = inos.clone();
            s.spawn(move || {
                for j in 0..PER {
                    if let Ok(ino) = m.create_dir(p, alloc::format!("d{t}_{j}").as_bytes(), 0o755, 0, 0) {
                        inos.lock().unwrap().push(ino);
                    }
                }
            });
        }
    });
    let mut v = inos.lock().unwrap().clone();
    let total = v.len();
    v.sort_unstable();
    v.dedup();
    assert_eq!(v.len(), total,
        "concurrent creates double-allocated an inode ({} dups of {}): allocator RMW is not serialized",
        total - v.len(), total);

    // Consistency: every recorded inode must be a real, readable dir on remount.
    drop(m);
    let m2 = ext4::Mount::open(disk as Arc<dyn BlockDevice>).unwrap();
    for &ino in v.iter() {
        let node = m2.read_inode(ino).unwrap_or_else(|e| panic!("inode {ino} unreadable after remount: {e:?}"));
        assert!(node.is_dir(), "inode {ino} should be a directory");
    }
}
