// Bulk transfer: how much fits in one message, and the loops that make a
// caller's request out of however much the server chose to move.

extern crate alloc;
use alloc::vec::Vec;

use crate::err::{NpError, NpResult};
use crate::uapi::{limits, op};
use super::{Client, FidRef};

/// Bytes one `Tread`/`Twrite` may carry.
///
/// Three bounds compose, and each exists for a different reason: the handle's
/// `iounit` is the SERVER's per-handle limit, `msize - IOHDRSZ` is what the
/// frame can hold once the envelope is accounted for, and `count` is what the
/// caller actually asked for. An `iounit` of zero means the server named no
/// limit, NOT a limit of zero — treating it literally makes every read return
/// nothing and the caller loop forever on a file it can never finish.
///
/// Pure, so the arithmetic is checkable without a server. # C: O(1)
pub fn transfer_size(iounit: u32, msize: u32, count: usize) -> usize {
    let envelope = msize.saturating_sub(limits::IOHDRSZ as u32) as usize;
    let mut n = if iounit == 0 { envelope } else { (iounit as usize).min(envelope) };
    if count < n { n = count; }
    n
}

/// Bytes one `Treaddir` may carry. The directory envelope is larger than the
/// I/O envelope, so reusing [`transfer_size`] here would let the client ask for
/// more than the reply frame can hold. # C: O(1)
pub fn readdir_size(iounit: u32, msize: u32, count: usize) -> usize {
    let envelope = msize.saturating_sub(limits::READDIRHDRSZ as u32) as usize;
    let mut n = if iounit == 0 { envelope } else { (iounit as usize).min(envelope) };
    if count < n { n = count; }
    n
}

impl Client {
    /// One `Tread`. Returns the bytes the server chose to give, which may be
    /// fewer than asked for; zero means end of file. # C: RPC
    pub fn read_once(&self, fid: &FidRef, offset: u64, buf: &mut [u8]) -> NpResult<usize> {
        let n = transfer_size(fid.iounit(), self.msize(), buf.len());
        if n == 0 { return Ok(0); }
        let reply = self.rpc(op::TREAD, |e| {
            e.u32(fid.fid)?; e.u64(offset)?; e.u32(n as u32)
        })?;
        let mut d = reply.dec();
        let data = d.data()?;
        // A server declaring more than it was asked for is a protocol fault,
        // not a large read: copying it would overrun the caller's buffer.
        if data.len() > n { return Err(NpError::BadMessage); }
        buf[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    /// Fill `buf` from `offset`, issuing as many reads as the frame size needs.
    /// Stops early at end of file, which is a SHORT result and not an error.
    /// # C: RPC per frame
    pub fn read(&self, fid: &FidRef, mut offset: u64, buf: &mut [u8]) -> NpResult<usize> {
        let mut done = 0usize;
        while done < buf.len() {
            let n = self.read_once(fid, offset, &mut buf[done..])?;
            if n == 0 { break; }
            done += n;
            offset += n as u64;
        }
        Ok(done)
    }

    /// One `Twrite`. Returns the bytes the server accepted. # C: RPC
    pub fn write_once(&self, fid: &FidRef, offset: u64, data: &[u8]) -> NpResult<usize> {
        let n = transfer_size(fid.iounit(), self.msize(), data.len());
        if n == 0 { return Ok(0); }
        let reply = self.rpc(op::TWRITE, |e| {
            e.u32(fid.fid)?; e.u64(offset)?; e.data(&data[..n])
        })?;
        let mut d = reply.dec();
        let written = d.u32()? as usize;
        // A server claiming to have written more than it was sent would make
        // the caller skip data that never reached the file.
        if written > n { return Err(NpError::BadMessage); }
        Ok(written)
    }

    /// Write all of `data`, issuing as many messages as the frame size needs. A
    /// server that accepts zero bytes has stalled; the loop stops rather than
    /// spinning. # C: RPC per frame
    pub fn write(&self, fid: &FidRef, mut offset: u64, data: &[u8]) -> NpResult<usize> {
        let mut done = 0usize;
        while done < data.len() {
            let n = self.write_once(fid, offset, &data[done..])?;
            if n == 0 { break; }
            done += n;
            offset += n as u64;
        }
        Ok(done)
    }

    /// One `Treaddir` at the opaque cookie `offset`.
    ///
    /// `offset` is the `offset` field of the LAST entry the previous call
    /// returned, never a byte count and never an entry index — a server is free
    /// to make it any value it can resume from. Returns the raw packed entry
    /// bytes for `crate::codec::DirEntries` to walk. # C: RPC
    pub fn readdir(&self, fid: &FidRef, offset: u64, count: usize) -> NpResult<Vec<u8>> {
        let n = readdir_size(fid.iounit(), self.msize(), count);
        let reply = self.rpc(op::TREADDIR, |e| {
            e.u32(fid.fid)?; e.u64(offset)?; e.u32(n as u32)
        })?;
        let mut d = reply.dec();
        let data = d.data()?;
        if data.len() > n { return Err(NpError::BadMessage); }
        let mut out = Vec::new();
        out.try_reserve_exact(data.len()).map_err(|_| NpError::NoMemory)?;
        out.extend_from_slice(data);
        Ok(out)
    }
}
