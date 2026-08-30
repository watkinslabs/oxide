//! Ext4 polled direct-I/O completion against a device that genuinely defers.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use block::{BlockCompletion, BlockDevice, BlockError, BlockOp, BlockRequest, MemDisk};
use sync::{Spinlock, TaskList};
use vfs::fs::FileSystem;
use vfs::file_ops::{DirectIo, DirectSubmit};
use vfs::{Dentry, File, OpenFlags, SuperBlock, VfsError};

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

struct PollDisk {
    inner: Arc<MemDisk<TaskList>>,
    parked: Spinlock<Vec<(BlockRequest, BlockCompletion)>, TaskList>,
    fail: AtomicBool,
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
        Arc::new(Self { inner, parked: Spinlock::new(Vec::new()), fail: AtomicBool::new(false) })
    }

    fn fail_next(&self) { self.fail.store(true, Ordering::Release); }
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
    fn flush(&self) -> Result<(), BlockError> { self.inner.flush() }
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

#[test]
fn polled_write_completes_only_after_device_poll_and_invalidates_cache() {
    let disk = PollDisk::from_image();
    let (m, _sb) = mount(disk.clone());
    let bs = m.state().mount.sb.block_size as usize;
    let inode = seeded_file(&m, bs);
    let mut cached = alloc::vec![0u8; bs];
    inode.read(&mut cached).expect("fault cache");

    let result = Arc::new(Spinlock::<Option<(Vec<u8>, Result<usize, VfsError>)>, TaskList>::new(None));
    let slot = result.clone();
    let direct = File::new(inode.inode().clone(), Dentry::new_root(inode.inode().clone()), OpenFlags::O_RDWR | OpenFlags::O_DIRECT);
    let replacement = alloc::vec![0xE7u8; bs];
    assert!(matches!(direct.submit_direct(DirectIo {
        write: true, off: 0, buf: replacement.clone(),
        done: alloc::boxed::Box::new(move |buf, res| { *slot.lock() = Some((buf, res)); }),
    }), DirectSubmit::Queued));
    assert!(result.lock().is_none(), "device completion is deferred until poll");
    assert_eq!(direct.iopoll(), Some(1));
    assert_eq!(result.lock().as_ref().expect("completion").1, Ok(bs));

    inode.set_pos(0);
    let mut got = alloc::vec![0u8; bs];
    inode.read(&mut got).expect("read after polled write");
    assert_eq!(got, replacement, "polled DIO invalidates the resident cache");
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
        done: alloc::boxed::Box::new(move |_buf, res| { *slot.lock() = Some(res); }),
    }), DirectSubmit::Queued));
    assert!(result.lock().is_none());
    assert_eq!(direct.iopoll(), Some(1));
    assert_eq!(*result.lock().as_ref().expect("error completion"), Err(VfsError::Eio));
}
