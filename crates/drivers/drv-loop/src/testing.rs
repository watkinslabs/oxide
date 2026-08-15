//! A backing store in memory, so the device and ioctl rules are exercised
//! with no filesystem, no mount and no disk.
//!
//! Compiled for tests and for the `hosted` feature only; a kernel build has
//! `backing::FileBacking` and nothing else.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use block::{BlockError, KResult};
use sync::{Spinlock, TaskList as LoopLockClass};

use crate::device::Backing;

pub struct Mem {
    bytes: Spinlock<Vec<u8>, LoopLockClass>,
    writable: bool,
    /// Bytes beyond this read as nothing at all — a sparse or truncated file.
    readable_len: Option<usize>,
    flushes: AtomicU32,
}

impl Mem {
    /// A zeroed, writable backing store of `len` bytes. # C: O(len)
    pub fn new(len: usize) -> Arc<Self> { Self::with(vec![0u8; len], true) }

    /// A backing store over `bytes`, writable or not. # C: O(1)
    pub fn with(bytes: Vec<u8>, writable: bool) -> Arc<Self> {
        Arc::new(Mem { bytes: Spinlock::new(bytes), writable, readable_len: None,
                       flushes: AtomicU32::new(0) })
    }

    /// A store `len` long of which only the first `readable` bytes can be
    /// read — a sparse or concurrently truncated file. # C: O(len)
    pub fn truncated(len: usize, readable: usize) -> Arc<Self> {
        Arc::new(Mem { bytes: Spinlock::new(vec![0xAA; len]), writable: true,
                       readable_len: Some(readable), flushes: AtomicU32::new(0) })
    }

    /// Read one byte of the store directly, bypassing the device. # C: O(1)
    pub fn peek(&self, at: usize) -> u8 { self.bytes.lock()[at] }

    /// Overwrite a range directly, bypassing the device. # C: O(len)
    pub fn poke(&self, at: usize, value: u8, len: usize) {
        self.bytes.lock()[at..at + len].fill(value);
    }

    /// Grow or shrink the store, as a file changing under a bound device.
    /// # C: O(len)
    pub fn resize(&self, len: usize) { self.bytes.lock().resize(len, 0); }

    /// How many flushes reached this store. # C: O(1)
    pub fn flushes(&self) -> u32 { self.flushes.load(Ordering::Relaxed) }
}

impl Backing for Mem {
    fn size_bytes(&self) -> u64 { self.bytes.lock().len() as u64 }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let src = self.bytes.lock();
        let limit = self.readable_len.unwrap_or(src.len());
        let start = off as usize;
        if start >= limit { return Ok(0); }
        let n = core::cmp::min(buf.len(), limit - start);
        buf[..n].copy_from_slice(&src[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        if !self.writable { return Err(BlockError::Eio); }
        let mut dst = self.bytes.lock();
        let start = off as usize;
        if start + buf.len() > dst.len() { return Err(BlockError::Enospc); }
        dst[start..start + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&self) -> KResult<()> { self.flushes.fetch_add(1, Ordering::Relaxed); Ok(()) }

    fn writable(&self) -> bool { self.writable }
}
