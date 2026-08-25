#![allow(unused_imports)]
//! Block-device page cache contract.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Inode as InodeClass, Spinlock};
use crate::blockdev::{BlockCompletion, BlockDevice, BlockRequest, MemDisk};
use crate::types::{BlockError, KResult, PAGE_BYTES};
use super::coherence::page_span;
use super::mapping::BdevMapping;
use super::{CoherentDev, sync_bdevs};

const BS: u32 = 512;
const PG: u64 = PAGE_BYTES as u64;

fn medium(blocks: u64) -> Arc<MemDisk<InodeClass>> { MemDisk::<InodeClass>::new(BS, blocks) }
fn mapping_over(dev: Arc<dyn BlockDevice>) -> Arc<BdevMapping> { BdevMapping::new(dev) }
fn on_medium(dev: &dyn BlockDevice, off: u64, len: usize) -> Vec<u8> {
    let first = off / BS as u64;
    let last_excl = (off + len as u64 + BS as u64 - 1) / BS as u64;
    let mut req = BlockRequest::new_read(first, (last_excl - first) as u32, BS);
    dev.submit_sync(&mut req).unwrap();
    let inner = (off - first * BS as u64) as usize;
    req.buffer[inner..inner + len].to_vec()
}

#[path = "tests/cache.rs"] mod cache;
#[path = "tests/writeback.rs"] mod writeback;
#[path = "tests/coherence.rs"] mod coherence_tests;
#[path = "tests/sync.rs"] mod sync_tests;
#[path = "tests/transfer.rs"] mod transfer;
