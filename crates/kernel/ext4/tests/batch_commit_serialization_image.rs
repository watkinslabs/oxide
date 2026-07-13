//! Batch metadata remains shadow-visible until journal and home writes finish.

extern crate alloc;
mod common;

use alloc::sync::Arc;
use std::sync::{Condvar, Mutex, mpsc};
use std::time::Duration;

use block::{BlockDevice, BlockOp, BlockRequest, KResult, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

struct BlockingWriteDev {
    inner: Arc<dyn BlockDevice>,
    state: Mutex<BlockState>,
    changed: Condvar,
}

#[derive(Default)]
struct BlockState {
    armed: bool,
    blocked: bool,
    released: bool,
}

impl BlockingWriteDev {
    fn new(inner: Arc<dyn BlockDevice>) -> Arc<Self> {
        Arc::new(Self { inner, state: Mutex::new(BlockState::default()), changed: Condvar::new() })
    }

    fn arm(&self) {
        *self.state.lock().unwrap() = BlockState { armed: true, blocked: false, released: false };
    }

    fn wait_until_blocked(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.blocked { state = self.changed.wait(state).unwrap(); }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.released = true;
        self.changed.notify_all();
    }
}

impl BlockDevice for BlockingWriteDev {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        if req.op == BlockOp::Write {
            let mut state = self.state.lock().unwrap();
            if state.armed {
                state.armed = false;
                state.blocked = true;
                self.changed.notify_all();
                while !state.released { state = self.changed.wait(state).unwrap(); }
            }
        }
        self.inner.submit_sync(req)
    }

    fn flush(&self) -> KResult<()> { self.inner.flush() }
}

fn fresh_disk() -> Arc<dyn BlockDevice> {
    let cap = IMAGE.len() as u64 / SECTOR as u64;
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest::new_write(0, cap as u32, IMAGE.to_vec());
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn metadata_read_uses_shadow_during_batch_commit_home_writes() {
    common::boot_hosted_pmm();
    let dev = BlockingWriteDev::new(fresh_disk());
    let mount = Arc::new(ext4::Mount::open(dev.clone()).unwrap());
    let root = mount.lookup_path(b"/").unwrap();

    mount.begin_batch();
    mount.create_file(root, b"staged", 0o644, 0, 0).unwrap();
    dev.arm();

    let commit_mount = mount.clone();
    let commit = std::thread::spawn(move || commit_mount.commit_batch());
    dev.wait_until_blocked();

    let (done_tx, done_rx) = mpsc::channel();
    let read_mount = mount.clone();
    let reader = std::thread::spawn(move || {
        done_tx.send(read_mount.read_inode(root)).unwrap();
    });

    done_rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
    dev.release();

    commit.join().unwrap().unwrap();
    reader.join().unwrap();
}
