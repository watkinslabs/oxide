//! The mapped device's I/O path: admit, split, map, remap.
//!
//! A submission to a mapped device is never handed to a target whole. It is
//! cut at every target boundary and at every boundary the target itself
//! declares, and each piece carries the slice of the payload that belongs to
//! it. Getting the slice arithmetic wrong writes the right bytes to the wrong
//! sector, which no error path reports, so the split and the slice are
//! computed in one place from one set of numbers.

extern crate alloc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult};

use super::{has_payload, MappedDevice};
use crate::defer::{admit, Admission};
use crate::split;
use crate::target::{DmIo, MapResult};
use crate::uapi::SECTOR_BYTES;

/// Submit one request, deferring or failing it per the device's live state.
/// # C: O(N_pieces)
pub fn submit(dev: &MappedDevice, mut request: BlockRequest, completion: block::BlockCompletion) {
    let (flags, table) = dev.with_state(|s| (s.flags, s.active.clone()));
    match admit(flags, table.is_some()) {
        Admission::Defer => { dev.park(request, completion); return; }
        Admission::Fail => { completion(request, Err(BlockError::Eio)); return; }
        Admission::Map => {}
    }
    let result = place(table.as_deref(), &mut request);
    completion(request, result);
}

/// Compatibility synchronous path. A device that is not accepting I/O cannot
/// park a caller that is waiting on its own stack, so this reports the retry
/// the caller can act on rather than losing the request.
/// # C: O(N_pieces)
pub fn submit_sync(dev: &MappedDevice, req: &mut BlockRequest) -> KResult<()> {
    let (flags, table) = dev.with_state(|s| (s.flags, s.active.clone()));
    match admit(flags, table.is_some()) {
        Admission::Defer => Err(BlockError::Eagain),
        Admission::Fail => Err(BlockError::Eio),
        Admission::Map => place(table.as_deref(), req),
    }
}

fn place(table: Option<&crate::table::Table>, req: &mut BlockRequest) -> KResult<()> {
    let Some(table) = table else { return Err(BlockError::Eio) };
    let sector = req.start_block;
    let n_sectors = req.len_blocks as u64;
    let payload = has_payload(req.op);
    let per_sector = if payload { SECTOR_BYTES as usize } else { 0 };

    if payload && req.buffer.len() != (n_sectors as usize) * (SECTOR_BYTES as usize) {
        return Err(BlockError::Einval);
    }

    let pieces = split::split(table, sector, n_sectors, per_sector).ok_or(BlockError::Einval)?;

    for p in &pieces {
        let entry = table.target(p.target).ok_or(BlockError::Eio)?;
        let mut data = if payload {
            let end = p.data_offset + (p.n_sectors as usize) * (SECTOR_BYTES as usize);
            req.buffer.get(p.data_offset..end).ok_or(BlockError::Einval)?.to_vec()
        } else {
            Vec::new()
        };
        let mut io = DmIo { op: req.op, sector: p.sector, n_sectors: p.n_sectors, data: &mut data };
        match entry.target.map(&mut io).map_err(|_| BlockError::Eio)? {
            MapResult::Submitted => {}
            MapResult::Kill => return Err(BlockError::Eio),
            // A synchronous submitter has nowhere to park, so a requeue is the
            // retryable error rather than a silent drop.
            MapResult::Requeue | MapResult::DelayRequeue => return Err(BlockError::Eagain),
            MapResult::Remapped { dev, sector } => {
                forward(&*dev, req.op, sector, p.n_sectors, &mut data)?;
            }
        }
        if payload && matches!(req.op, BlockOp::Read) {
            let end = p.data_offset + (p.n_sectors as usize) * (SECTOR_BYTES as usize);
            if data.len() != end - p.data_offset { return Err(BlockError::Eio); }
            req.buffer[p.data_offset..end].copy_from_slice(&data);
        }
    }
    Ok(())
}

/// Hand one piece to a member device, converting the device-mapper sector
/// address into that device's own block addressing. A member whose block size
/// exceeds a sector cannot be given an unaligned piece; refusing is the only
/// safe answer, because rounding either direction moves the data.
/// # C: O(piece)
pub fn forward(dev: &dyn BlockDevice, op: BlockOp, sector: u64, n_sectors: u64,
                data: &mut Vec<u8>) -> KResult<()> {
    let bs = dev.block_size() as u64;
    if bs == 0 { return Err(BlockError::Einval); }
    let byte_off = sector.checked_mul(SECTOR_BYTES).ok_or(BlockError::Einval)?;
    let byte_len = n_sectors.checked_mul(SECTOR_BYTES).ok_or(BlockError::Einval)?;
    if byte_off % bs != 0 || byte_len % bs != 0 { return Err(BlockError::Einval); }

    let start_block = byte_off / bs;
    let len_blocks = u32::try_from(byte_len / bs).map_err(|_| BlockError::Einval)?;
    let mut req = match op {
        BlockOp::Read => BlockRequest::new_read(start_block, len_blocks, bs as u32),
        BlockOp::Write => BlockRequest::new_write(start_block, len_blocks, core::mem::take(data)),
        BlockOp::WriteZeroes { no_unmap } => BlockRequest::new_write_zeroes(start_block, len_blocks, no_unmap),
        BlockOp::Discard => BlockRequest::new_discard(start_block, len_blocks),
        BlockOp::Flush => BlockRequest::new_flush(),
    };
    let r = dev.submit_sync(&mut req);
    if matches!(op, BlockOp::Read) && r.is_ok() { *data = req.buffer; }
    r
}
