//! Ext4 polled direct-I/O completion against a device that genuinely defers.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use block::{BlockCompletion, BlockDevice, BlockError, BlockOp, BlockRequest, MemDisk};
use sync::{Spinlock, TaskList};
use vfs::fs::FileSystem;
use vfs::file_ops::{DirectIo, DirectSubmit};
use vfs::{Dentry, File, OpenFlags, SuperBlock, SyncMode, VfsError};

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

struct PollDisk {
    inner: Arc<MemDisk<TaskList>>,
    parked: Spinlock<Vec<(BlockRequest, BlockCompletion)>, TaskList>,
    fail: AtomicBool,
    flushes: AtomicU32,
}

impl PollDisk {
    fn from_image() -> Arc<Self> {
        let cap = IMAGE.len() as u64 / SECTOR as u64;
        let inner = MemDisk::new(SECTOR, cap);
        let mut seed = BlockRequest {
            op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
            buffer: IMAGE.to_vec(), ..Default::default()
        };
        inner.submit_sync(&mut seed).expect("seed poll disk");
        Arc::new(Self { inner, parked: Spinlock::new(Vec::new()), fail: AtomicBool::new(false), flushes: AtomicU32::new(0) })
    }

    fn fail_next(&self) { self.fail.store(true, Ordering::Release); }

    fn flush_count(&self) -> u32 { self.flushes.load(Ordering::Acquire) }
}

impl BlockDevice for PollDisk {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
        if request.polled {
            self.parked.lock().push((request, completion));
        } else {
            let mut request = request;
            let result = self.inner.submit_sync(&mut request);
            completion(request, result);
        }
    }
    fn submit_sync(&self, request: &mut BlockRequest) -> Result<(), BlockError> {
        self.inner.submit_sync(request)
    }
    fn flush(&self) -> Result<(), BlockError> {
        self.flushes.fetch_add(1, Ordering::AcqRel);
        self.inner.flush()
    }
    fn can_poll(&self) -> bool { true }
    fn poll_completions(&self) -> usize {
        let parked = core::mem::take(&mut *self.parked.lock());
        let count = parked.len();
        for (mut request, done) in parked {
            let result = if self.fail.swap(false, Ordering::AcqRel) {
                Err(BlockError::Eio)
            } else { self.inner.submit_sync(&mut request) };
            done(request, result);
        }
        count
    }
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("open ext4");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xD10, String::from("ext4"));
    (m, sb)
}

fn seeded_file(m: &Arc<ext4::rootfs::Ext4Mount>, bs: usize) -> Arc<File> {
    let st = m.state();
    let root = st.lookup_path(b"/").expect("root");
    let ino = st.mount.create_file(root, b"polled.bin", 0o644, 0, 0).expect("create");
    st.mount.write_at(ino, 0, &alloc::vec![0x31u8; bs]).expect("seed file");
    let inode = st.wrap_file(ino).expect("wrap file");
    File::new(inode.clone(), Dentry::new_root(inode), OpenFlags::O_RDWR)
}

fn preallocated_file(m: &Arc<ext4::rootfs::Ext4Mount>, bs: usize, blocks: usize)
    -> (Arc<File>, u32) {
    let st = m.state();
    let root = st.lookup_path(b"/").expect("root");
    let ino = st.mount.create_file(root, b"polled-prealloc.bin", 0o644, 0, 0).expect("create");
    st.mount.fallocate_inode(ino, 0, (bs * blocks) as u64, false).expect("preallocate");
    let inode = st.wrap_file(ino).expect("wrap file");
    (File::new(inode.clone(), Dentry::new_root(inode), OpenFlags::O_RDWR), ino)
}

fn hole_file(m: &Arc<ext4::rootfs::Ext4Mount>, bs: usize) -> (Arc<File>, u32) {
    let st = m.state();
    let root = st.lookup_path(b"/").expect("root");
    let ino = st.mount.create_file(root, b"polled-hole.bin", 0o644, 0, 0).expect("create");
    st.mount.set_inode_size(ino, (3 * bs) as u64).expect("size");
    let inode = st.wrap_file(ino).expect("wrap file");
    let file = File::new(inode.clone(), Dentry::new_root(inode),
                         OpenFlags::O_RDWR | OpenFlags::O_DIRECT);
    for block in [0, 2] {
        st.mount.fallocate_inode(ino, (block * bs) as u64, bs as u64, true)
            .expect("preallocate mapped block");
        file.pwrite(&vec![0x11; bs], (block * bs) as i64)
            .expect("initialize mapped block");
    }
    (file, ino)
}

#[test]
fn polled_write_completes_only_after_device_poll_and_invalidates_cache() {
    let disk = PollDisk::from_image();
    let (m, _sb) = mount(disk.clone());
    let bs = m.state().mount.sb.block_size as usize;
    let inode = seeded_file(&m, bs);
    let mut cached = alloc::vec![0u8; bs];
    inode.read(&mut cached).expect("fault cache");

    let result = Arc::new(Spinlock::<Option<(Vec<u8>, Result<usize, VfsError>, SyncMode)>, TaskList>::new(None));
    let slot = result.clone();
    let direct = File::new(inode.inode().clone(), Dentry::new_root(inode.inode().clone()), OpenFlags::O_RDWR | OpenFlags::O_DIRECT);
    let completion_file = direct.clone();
    let replacement = alloc::vec![0xE7u8; bs];
    assert!(matches!(direct.submit_direct(DirectIo {
        write: true, off: 0, buf: replacement.clone(),
        sync_mode: SyncMode { dsync: true, sync: false },
        done: alloc::boxed::Box::new(move |buf, res, sync| {
            let res = match res {
                Ok(n) => completion_file.complete_direct_write(0, n, sync).map(|()| n),
                Err(e) => Err(e),
            };
            *slot.lock() = Some((buf, res, sync));
        }),
    }), DirectSubmit::Queued));
    assert!(result.lock().is_none(), "device completion is deferred until poll");
    assert_eq!(direct.iopoll(), Some(1));
    assert_eq!(result.lock().as_ref().expect("completion").1, Ok(bs));
    assert_eq!(result.lock().as_ref().expect("completion").2,
        SyncMode { dsync: true, sync: false });
    assert!(disk.flush_count() > 0, "RWF_DSYNC completion must flush the device");

    inode.set_pos(0);
    let mut got = alloc::vec![0u8; bs];
    inode.read(&mut got).expect("read after polled write");
    assert_eq!(got, replacement, "polled DIO invalidates the resident cache");
}

#[test]
fn polled_write_honors_device_aligned_subfilesystem_offset() {
    let disk = PollDisk::from_image();
    let (m, _sb) = mount(disk.clone());
    let bs = m.state().mount.sb.block_size as usize;
    let file = seeded_file(&m, bs);
    let direct = File::new(file.inode().clone(), Dentry::new_root(file.inode().clone()),
                           OpenFlags::O_RDWR | OpenFlags::O_DIRECT);
    let replacement = alloc::vec![0xD4u8; 512];
    let result = Arc::new(Spinlock::<Option<Result<usize, VfsError>>, TaskList>::new(None));
    let slot = result.clone();
    let completion_file = direct.clone();
    assert!(matches!(direct.submit_direct(DirectIo {
        write: true, off: 512, buf: replacement,
        sync_mode: SyncMode::default(),
        done: alloc::boxed::Box::new(move |_buf, res, sync| {
            let res = match res {
                Ok(n) => completion_file.complete_direct_write(512, n, sync).map(|()| n),
                Err(e) => Err(e),
            };
            *slot.lock() = Some(res);
        }),
    }), DirectSubmit::Queued));
    assert_eq!(direct.iopoll(), Some(1));
    assert_eq!(*result.lock().as_ref().expect("partial completion"), Ok(512));

    direct.set_pos(0);
    let mut got = alloc::vec![0u8; bs];
    direct.inode().read(0, &mut got).expect("read partial result");
    assert!(got[..512].iter().all(|&b| b == 0x31));
    assert!(got[512..1024].iter().all(|&b| b == 0xD4));
    assert!(got[1024..].iter().all(|&b| b == 0x31));
}

#[test]
fn polled_write_persists_completion_timestamp_across_remount() {
    let disk = PollDisk::from_image();
    let (m, sb) = mount(disk.clone());
    let bs = m.state().mount.sb.block_size as usize;
    let file = seeded_file(&m, bs);
    let inode = file.inode().clone();
    let before_mtime = inode.mtime().expect("initial mtime");
    let before_ctime = inode.ctime().expect("initial ctime");
    let result = Arc::new(Spinlock::<Option<Result<usize, VfsError>>, TaskList>::new(None));
    let slot = result.clone();
    let completion_file = file.clone();
    assert!(matches!(file.submit_direct(DirectIo {
        write: true, off: 0, buf: alloc::vec![0xA9u8; bs],
        sync_mode: SyncMode { dsync: true, sync: true },
        done: alloc::boxed::Box::new(move |_buf, res, sync| {
            let res = match res {
                Ok(n) => completion_file.complete_direct_write(0, n, sync).map(|()| n),
                Err(e) => Err(e),
            };
            *slot.lock() = Some(res);
        }),
    }), DirectSubmit::Queued));
    assert!(result.lock().is_none());
    assert_eq!(file.iopoll(), Some(1));
    assert_eq!(*result.lock().as_ref().expect("completion"), Ok(bs));
    assert!(disk.flush_count() > 0, "RWF_SYNC completion must flush the device");
    let after_mtime = inode.mtime().expect("completed mtime");
    let after_ctime = inode.ctime().expect("completed ctime");
    assert!(after_mtime >= before_mtime, "direct write must not move mtime backwards");
    assert!(after_ctime >= before_ctime, "direct write must not move ctime backwards");
    let ino = inode.ino() as u32;
    drop(file);
    drop(sb);
    drop(m);
    let (m2, _sb2) = mount(disk);
    let persisted = m2.state().mount.read_inode(ino).expect("inode after remount");
    assert_eq!(persisted.mtime, after_mtime, "direct-write mtime survives remount");
    assert_eq!(persisted.ctime, after_ctime, "direct-write ctime survives remount");
}

#[test]
fn polled_write_error_reaches_the_completion_owner() {
    let disk = PollDisk::from_image();
    let (m, _sb) = mount(disk.clone());
    let bs = m.state().mount.sb.block_size as usize;
    let inode = seeded_file(&m, bs);
    let result = Arc::new(Spinlock::<Option<Result<usize, VfsError>>, TaskList>::new(None));
    let slot = result.clone();
    let direct = File::new(inode.inode().clone(), Dentry::new_root(inode.inode().clone()), OpenFlags::O_RDWR | OpenFlags::O_DIRECT);
    disk.fail_next();
    assert!(matches!(direct.submit_direct(DirectIo {
        write: true, off: 0, buf: alloc::vec![0xF4u8; bs],
        sync_mode: SyncMode::default(),
        done: alloc::boxed::Box::new(move |_buf, res, _sync| { *slot.lock() = Some(res); }),
    }), DirectSubmit::Queued));
    assert!(result.lock().is_none());
    assert_eq!(direct.iopoll(), Some(1));
    assert_eq!(*result.lock().as_ref().expect("error completion"), Err(VfsError::Eio));
}

#[test]
fn polled_write_converts_only_the_completed_unwritten_range() {
    let disk = PollDisk::from_image();
    let (m, _sb) = mount(disk.clone());
    let bs = m.state().mount.sb.block_size as usize;
    let (file, ino) = preallocated_file(&m, bs, 3);
    let result = Arc::new(Spinlock::<Option<Result<usize, VfsError>>, TaskList>::new(None));
    let slot = result.clone();
    assert!(matches!(file.submit_direct(DirectIo {
        write: true, off: bs as u64, buf: alloc::vec![0xB6u8; bs],
        sync_mode: SyncMode::default(),
        done: alloc::boxed::Box::new(move |_buf, res, _sync| { *slot.lock() = Some(res); }),
    }), DirectSubmit::Queued));
    assert!(result.lock().is_none());
    assert_eq!(file.iopoll(), Some(1));
    assert_eq!(*result.lock().as_ref().expect("completion"), Ok(bs));
    let runs = m.state().mount.extent_map(ino).expect("extent map");
    assert!(runs.iter().any(|&(logical, _phys, len, unwritten)|
        logical == 0 && len >= 1 && unwritten));
    assert!(runs.iter().any(|&(logical, _phys, len, unwritten)|
        logical == 1 && len >= 1 && !unwritten));
    assert!(runs.iter().any(|&(logical, _phys, len, unwritten)|
        logical == 2 && len >= 1 && unwritten));
}

#[test]
fn polled_write_allocates_and_converts_an_in_file_hole() {
    let disk = PollDisk::from_image();
    let (m, _sb) = mount(disk.clone());
    let bs = m.state().mount.sb.block_size as usize;
    let (file, ino) = hole_file(&m, bs);
    let result = Arc::new(Spinlock::<Option<Result<usize, VfsError>>, TaskList>::new(None));
    let slot = result.clone();
    assert!(matches!(file.submit_direct(DirectIo {
        write: true, off: bs as u64, buf: alloc::vec![0xC7u8; bs],
        sync_mode: SyncMode::default(),
        done: alloc::boxed::Box::new(move |_buf, res, _sync| { *slot.lock() = Some(res); }),
    }), DirectSubmit::Queued));
    assert!(result.lock().is_none());
    assert_eq!(file.iopoll(), Some(1));
    assert_eq!(*result.lock().as_ref().expect("completion"), Ok(bs));
    let runs = m.state().mount.extent_map(ino).expect("extent map");
    assert!(runs.iter().any(|&(logical, _phys, len, unwritten)|
        logical == 0 && len >= 1 && !unwritten));
    assert!(runs.iter().any(|&(logical, _phys, len, unwritten)|
        logical == 1 && len >= 1 && !unwritten));
    assert!(runs.iter().any(|&(logical, _phys, len, unwritten)|
        logical == 2 && len >= 1 && !unwritten));
}
