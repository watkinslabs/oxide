use alloc::vec::Vec;

use block::{BlockDevice, BlockRequest};

use super::MountError;

/// Write `data` to `dev` at byte offset `byte_off`. RMW for any
/// partial-block write — `data` need not be sector-multiple. A
/// block-aligned, whole-block-multiple write SKIPS the RMW read
/// (the read-back would be fully overwritten): a fresh large-file
/// write (systemd-hwdb's 13.5MB) is all full-block writes, so the
/// pre-read doubled every data op — 27k useless serialized reads.
/// Direct device write only — does NOT consult any journal scope.
/// # C: O(data.len() / sector_size) I/O (+1 RMW read only if unaligned)
pub(crate) fn write_byte_range(dev: &dyn BlockDevice, byte_off: u64, data: &[u8])
    -> Result<(), MountError>
{
    let bs = dev.block_size() as u64;
    let first_blk = byte_off / bs;
    let last_byte = byte_off + data.len() as u64;
    let last_blk_excl = (last_byte + bs - 1) / bs;
    let n_blocks = (last_blk_excl - first_blk) as u32;
    // Fast path: byte_off block-aligned AND data covers whole blocks → the
    // write fully specifies every touched block, so the pre-read is dead I/O.
    if byte_off % bs == 0 && (data.len() as u64) % bs == 0 {
        let mut wreq = BlockRequest::new_write(first_blk, n_blocks, data.to_vec());
        dev.submit_sync(&mut wreq).map_err(|_| MountError::BlockIo)?;
        return Ok(());
    }
    let mut full = BlockRequest::new_read(first_blk, n_blocks, dev.block_size());
    dev.submit_sync(&mut full).map_err(|_| MountError::BlockIo)?;
    let inner_off = (byte_off - first_blk * bs) as usize;
    full.buffer[inner_off .. inner_off + data.len()].copy_from_slice(data);
    let mut wreq = BlockRequest::new_write(first_blk, n_blocks, full.buffer);
    dev.submit_sync(&mut wreq).map_err(|_| MountError::BlockIo)?;
    Ok(())
}

/// Read `len` bytes from `dev` starting at byte `byte_off`.
/// Translates to whole-block reads under the hood.
/// # C: O(1)
pub(super) fn read_byte_range(dev: &dyn BlockDevice, byte_off: u64, len: usize)
    -> Result<Vec<u8>, MountError>
{
    let bs = dev.block_size() as u64;
    let first_blk = byte_off / bs;
    let last_byte = byte_off + len as u64;
    let last_blk_excl = (last_byte + bs - 1) / bs;
    let n_blocks = (last_blk_excl - first_blk) as u32;
    let mut req = BlockRequest::new_read(first_blk, n_blocks, dev.block_size());
    dev.submit_sync(&mut req).map_err(|_| MountError::BlockIo)?;
    let inner_off = (byte_off - first_blk * bs) as usize;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&req.buffer[inner_off .. inner_off + len]);
    Ok(out)
}

/// Crate-public alias so submodules (`balloc`, `extent_rw`, …) can
/// call the read helper without re-implementing block-window math.
#[inline]
pub(crate) fn read_byte_range_pub(dev: &dyn BlockDevice, byte_off: u64, len: usize)
    -> Result<Vec<u8>, MountError>
{
    read_byte_range(dev, byte_off, len)
}
