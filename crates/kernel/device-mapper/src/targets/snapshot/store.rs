//! Where a snapshot's exceptions live: nowhere, or on the copy-out device.
//!
//! The persistent store's on-disk layout is an ABI — a snapshot written by one
//! implementation is read by another — so the header and record encodings are
//! byte-exact and round-tripped by test.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp};

use super::exception::Exception;
use crate::uapi::SECTOR_BYTES;

/// Magic word at the start of a persistent store.
pub const SNAP_MAGIC: u32 = 0x7041_6e53;
/// On-disk metadata version this implementation writes.
pub const SNAPSHOT_DISK_VERSION: u32 = 1;
/// Chunks the header occupies at the start of the store.
pub const NUM_SNAPSHOT_HDR_CHUNKS: u64 = 1;
/// Bytes one exception record occupies on disk.
pub const DISK_EXCEPTION_BYTES: usize = 16;
/// Bytes the header occupies, of which the rest of its chunk is padding.
pub const DISK_HEADER_BYTES: usize = 16;

/// The header at chunk zero of a persistent store.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DiskHeader {
    /// Whether the store's contents can be trusted. A store that was being
    /// written when the machine stopped is marked invalid and stays that way:
    /// there is no way to tell which exceptions completed.
    pub valid: bool,
    /// Metadata version.
    pub version: u32,
    /// Chunk size in 512-byte sectors.
    pub chunk_size: u32,
}

impl DiskHeader {
    /// Encode into the first bytes of a chunk. # C: O(1)
    pub fn encode(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&SNAP_MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&u32::from(self.valid).to_le_bytes());
        out[8..12].copy_from_slice(&self.version.to_le_bytes());
        out[12..16].copy_from_slice(&self.chunk_size.to_le_bytes());
    }

    /// Decode, rejecting a store that is not one or is a version this
    /// implementation does not know how to read. # C: O(1)
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < DISK_HEADER_BYTES { return None; }
        let magic = u32::from_le_bytes(buf[0..4].try_into().ok()?);
        if magic != SNAP_MAGIC { return None; }
        let version = u32::from_le_bytes(buf[8..12].try_into().ok()?);
        if version != SNAPSHOT_DISK_VERSION { return None; }
        Some(Self {
            valid: u32::from_le_bytes(buf[4..8].try_into().ok()?) != 0,
            version,
            chunk_size: u32::from_le_bytes(buf[12..16].try_into().ok()?),
        })
    }
}

/// Encode one record. # C: O(1)
pub fn encode_exception(e: &Exception, out: &mut [u8]) {
    out[0..8].copy_from_slice(&e.old_chunk.to_le_bytes());
    out[8..16].copy_from_slice(&e.new_chunk.to_le_bytes());
}

/// Decode one record. A zero origin chunk terminates an area, which is why a
/// store never allocates chunk zero to an exception. # C: O(1)
pub fn decode_exception(buf: &[u8]) -> Option<Exception> {
    if buf.len() < DISK_EXCEPTION_BYTES { return None; }
    let old_chunk = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    if old_chunk == 0 { return None; }
    Some(Exception { old_chunk, new_chunk: u64::from_le_bytes(buf[8..16].try_into().ok()?) })
}

/// Chunk index the metadata area `area` starts at.
///
/// Metadata areas are interleaved with the data they describe: one area chunk
/// followed by the chunks its records point at. # C: O(1)
pub const fn area_location(exceptions_per_area: u64, area: u64) -> u64 {
    NUM_SNAPSHOT_HDR_CHUNKS + (exceptions_per_area + 1) * area
}

/// Next free chunk, stepped past a metadata area if it landed on one. A data
/// chunk allocated on top of an area destroys the records it holds.
/// # C: O(1)
pub const fn skip_metadata(exceptions_per_area: u64, next_free: u64) -> u64 {
    let stride = exceptions_per_area + 1;
    if next_free % stride == NUM_SNAPSHOT_HDR_CHUNKS { next_free + 1 } else { next_free }
}

/// Records one metadata area holds. # C: O(1)
pub const fn exceptions_per_area(chunk_sectors: u64) -> u64 {
    (chunk_sectors * SECTOR_BYTES) / (DISK_EXCEPTION_BYTES as u64)
}

/// Where a snapshot's exceptions are kept.
pub trait ExceptionStore: Send + Sync {
    /// Read whatever the store already holds. # C: O(N_exceptions)
    fn read_metadata(&mut self) -> Vec<Exception>;
    /// Choose the destination chunk for the next exception. # C: O(1)
    fn prepare_exception(&mut self) -> Option<u64>;
    /// Make an exception durable. # C: depends on store
    fn commit_exception(&mut self, e: Exception) -> bool;
    /// Chunks handed out so far. # C: O(1)
    fn used_chunks(&self) -> u64;
    /// Chunks the store can hold in total. # C: O(1)
    fn total_chunks(&self) -> u64;
    /// Sectors of the store spent on metadata rather than data. # C: O(1)
    fn metadata_sectors(&self) -> u64;
    /// Letter the status report prints for this store type. # C: O(1)
    fn kind(&self) -> &'static str;
}

/// A store that keeps nothing: the snapshot dies with the machine.
pub struct TransientStore {
    chunk_sectors: u64,
    next_free: u64,
    total: u64,
}

impl TransientStore {
    /// A store over a device of `device_sectors`. # C: O(1)
    pub fn new(chunk_sectors: u64, device_sectors: u64) -> Self {
        Self { chunk_sectors, next_free: 0, total: device_sectors / chunk_sectors }
    }
}

impl ExceptionStore for TransientStore {
    fn read_metadata(&mut self) -> Vec<Exception> { Vec::new() }
    fn prepare_exception(&mut self) -> Option<u64> {
        if self.next_free >= self.total { return None; }
        let c = self.next_free;
        self.next_free += 1;
        Some(c)
    }
    fn commit_exception(&mut self, _e: Exception) -> bool { true }
    fn used_chunks(&self) -> u64 { self.next_free }
    fn total_chunks(&self) -> u64 { self.total }
    fn metadata_sectors(&self) -> u64 { 0 }
    fn kind(&self) -> &'static str { "N" }
    }

/// A store written to the copy-out device, so the snapshot survives a reboot.
pub struct PersistentStore {
    dev: Arc<dyn BlockDevice>,
    chunk_sectors: u64,
    exceptions_per_area: u64,
    total: u64,
    next_free: u64,
    /// Records buffered for the current area, flushed when it fills.
    pending: Vec<Exception>,
    current_area: u64,
    valid: bool,
}

impl PersistentStore {
    /// Open or create a store on `dev`. # C: O(1)
    pub fn new(dev: Arc<dyn BlockDevice>, chunk_sectors: u64) -> Self {
        let total = dev.capacity_blocks() * (dev.block_size() as u64) / SECTOR_BYTES / chunk_sectors;
        Self {
            dev, chunk_sectors,
            exceptions_per_area: exceptions_per_area(chunk_sectors),
            total,
            // Chunk zero is the header, and the first metadata area follows
            // it, so the first data chunk is the one after that.
            next_free: NUM_SNAPSHOT_HDR_CHUNKS + 1,
            pending: Vec::new(), current_area: 0, valid: true,
        }
    }

    /// Write the header, marking the store valid or not. # C: O(chunk)
    pub fn write_header(&mut self, valid: bool) -> bool {
        let mut buf = alloc::vec![0u8; (self.chunk_sectors * SECTOR_BYTES) as usize];
        DiskHeader { valid, version: SNAPSHOT_DISK_VERSION, chunk_size: self.chunk_sectors as u32 }
            .encode(&mut buf);
        self.valid = valid;
        self.chunk_write(0, &buf)
    }

    fn chunk_write(&self, chunk: u64, data: &[u8]) -> bool {
        let mut d = data.to_vec();
        crate::device::io::forward(&*self.dev, BlockOp::Write,
            chunk * self.chunk_sectors, self.chunk_sectors, &mut d).is_ok()
    }

    fn chunk_read(&self, chunk: u64) -> Option<Vec<u8>> {
        let mut d = Vec::new();
        crate::device::io::forward(&*self.dev, BlockOp::Read,
            chunk * self.chunk_sectors, self.chunk_sectors, &mut d).ok()?;
        Some(d)
    }

    fn flush_area(&mut self) -> bool {
        let chunk = area_location(self.exceptions_per_area, self.current_area);
        let mut buf = alloc::vec![0u8; (self.chunk_sectors * SECTOR_BYTES) as usize];
        for (i, e) in self.pending.iter().enumerate() {
            encode_exception(e, &mut buf[i * DISK_EXCEPTION_BYTES..(i + 1) * DISK_EXCEPTION_BYTES]);
        }
        self.chunk_write(chunk, &buf)
    }
}

impl ExceptionStore for PersistentStore {
    fn read_metadata(&mut self) -> Vec<Exception> {
        let Some(head) = self.chunk_read(0) else { self.valid = false; return Vec::new() };
        let Some(h) = DiskHeader::decode(&head) else { self.valid = false; return Vec::new() };
        if !h.valid { self.valid = false; return Vec::new(); }
        let mut out = Vec::new();
        let mut area = 0u64;
        // Areas are read in order and the walk stops at the first incomplete
        // one: a later area cannot hold records the earlier one does not,
        // because they are filled in order.
        loop {
            let chunk = area_location(self.exceptions_per_area, area);
            if chunk >= self.total { break; }
            let Some(buf) = self.chunk_read(chunk) else { break };
            let mut found = 0u64;
            for i in 0..self.exceptions_per_area as usize {
                match decode_exception(&buf[i * DISK_EXCEPTION_BYTES..(i + 1) * DISK_EXCEPTION_BYTES]) {
                    Some(e) => { out.push(e); found += 1; }
                    None => break,
                }
            }
            if found < self.exceptions_per_area { break; }
            area += 1;
        }
        self.current_area = area;
        self.next_free = out.iter().map(|e| e.dest() + e.len()).max()
            .unwrap_or(NUM_SNAPSHOT_HDR_CHUNKS + 1)
            .max(area_location(self.exceptions_per_area, area) + 1);
        out
    }

    fn prepare_exception(&mut self) -> Option<u64> {
        if !self.valid { return None; }
        let chunk = skip_metadata(self.exceptions_per_area, self.next_free);
        if chunk >= self.total { return None; }
        self.next_free = chunk + 1;
        Some(chunk)
    }

    fn commit_exception(&mut self, e: Exception) -> bool {
        if !self.valid { return false; }
        self.pending.push(e);
        if self.pending.len() as u64 >= self.exceptions_per_area {
            if !self.flush_area() { self.valid = false; return false; }
            self.pending.clear();
            self.current_area += 1;
        } else if !self.flush_area() {
            self.valid = false;
            return false;
        }
        true
    }

    fn used_chunks(&self) -> u64 { self.next_free.saturating_sub(NUM_SNAPSHOT_HDR_CHUNKS + 1) }
    fn total_chunks(&self) -> u64 { self.total }
    fn metadata_sectors(&self) -> u64 {
        (NUM_SNAPSHOT_HDR_CHUNKS + self.current_area + 1) * self.chunk_sectors
    }
    fn kind(&self) -> &'static str { "P" }
}
