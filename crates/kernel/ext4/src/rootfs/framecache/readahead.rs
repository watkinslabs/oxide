//! Asynchronous ext4 page-cache look-ahead, matching Linux's async readahead.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::Ext4FrameStore;

struct Job {
    store: Arc<Ext4FrameStore>,
    start: u64,
    pages: u64,
}

#[cfg(target_os = "oxide-kernel")]
fn run(raw: usize) {
    // SAFETY: `raw` is produced by `Box::into_raw` below and queued exactly
    // once; the workqueue invokes this function before the job is reclaimed.
    let job = unsafe { Box::from_raw(raw as *mut Job) };
    job.store.readahead_sync(job.start, job.pages);
    job.store.readahead_queued.store(false, Ordering::Release);
}

pub(super) fn schedule(store: &Ext4FrameStore, start: u64, pages: u64) {
    if pages == 0 || store.readahead_queued.swap(true, Ordering::AcqRel) { return; }
    let owner = store.self_arc();
    let raw = Box::into_raw(Box::new(Job { store: owner, start, pages }));
    #[cfg(target_os = "oxide-kernel")]
    if sched::live::workqueue::queue_work(run, raw as usize) { return; }
    // Hosted tests have no kernel worker. Run synchronously so the behavior is
    // still tested rather than silently discarding the read-ahead request.
    // SAFETY: queue_work returned false, so ownership remains here.
    let job = unsafe { Box::from_raw(raw) };
    job.store.readahead_sync(job.start, job.pages);
    job.store.readahead_queued.store(false, Ordering::Release);
}
