//! The work behind each loop ioctl.
//!
//! These take inputs a caller has already resolved — a device number, an open
//! description, a decoded wire struct — and return what the caller should
//! report. Copying to and from user memory, resolving a descriptor, and
//! checking the caller's privilege belong to the shim above; none of it
//! happens here, which is what lets every rule below be tested.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::config::{flags_after_configure, flags_after_set_status, window_changed, window_from_info, Window};
use crate::device::{Backing, LoopDevice};
use crate::size::{capacity_sectors, validate_block_size};
use crate::uapi::LoopInfo64;

/// A block error, as an errno. The block layer's vocabulary is narrower than
/// the ioctl ABI's, so the mapping is explicit rather than numeric. # C: O(1)
fn errno_of(err: block::BlockError) -> Errno {
    match err {
        block::BlockError::Enxio => Errno::Enxio,
        block::BlockError::Ebusy => Errno::Ebusy,
        block::BlockError::Einval => Errno::Einval,
        block::BlockError::Enospc => Errno::Enospc,
        block::BlockError::Enomem => Errno::Enomem,
        block::BlockError::Eagain => Errno::Eagain,
        block::BlockError::Eopnotsupp => Errno::Eopnotsupp,
        block::BlockError::Eio => Errno::Eio,
    }
}

/// `LOOP_SET_FD`: bind an open description with a default window.
///
/// The description's access mode decides whether the device is writable, and
/// a description that cannot be written yields a read-only device rather than
/// one that fails every write later.
/// # C: O(1)
pub fn set_fd(dev: &LoopDevice, backing: Arc<dyn Backing>, writable: bool) -> Result<(), Errno> {
    configure(dev, backing, writable, LoopInfo64::default(), 0)
}

/// `LOOP_CONFIGURE`: bind and configure in one step.
///
/// The refusal order is the caller's information: the window is validated
/// before the flags, and the block size last, so a request wrong in several
/// ways reports the same one every time.
/// # C: O(1)
pub fn configure(dev: &LoopDevice, backing: Arc<dyn Backing>, writable: bool,
                 info: LoopInfo64, block_size: u32) -> Result<(), Errno> {
    let window = window_from_info(&info)?;
    let flags = flags_after_configure(info.lo_flags, writable)?;
    let bsize = if block_size == 0 { DEFAULT_BLOCK_SIZE } else { validate_block_size(block_size)? };
    dev.bind(backing, window, flags, bsize).map_err(errno_of)
}

/// Logical block size a device takes when the caller names none.
pub const DEFAULT_BLOCK_SIZE: u32 = 512;

/// `LOOP_CLR_FD`: drop the backing description. # C: O(1)
pub fn clr_fd(dev: &LoopDevice) -> Result<(), Errno> { dev.unbind().map_err(errno_of) }

/// `LOOP_SET_STATUS64`: move the window and adjust the flags the caller owns.
///
/// Only a request that actually moves the window re-reads the size, which is
/// the reference's behaviour and keeps a status update from disturbing a
/// device whose backing file is being written to.
/// # C: O(1)
pub fn set_status(dev: &LoopDevice, info: LoopInfo64) -> Result<(), Errno> {
    let next = window_from_info(&info)?;
    let (current, flags, _) = dev.status().map_err(errno_of)?;
    let flags = flags_after_set_status(flags, info.lo_flags);
    if !window_changed(&current, &next) {
        // Same window: only the flags and the name move.
        return dev.set_window(Window { offset: current.offset, sizelimit: current.sizelimit,
                                       file_name: next.file_name }, flags).map_err(errno_of);
    }
    dev.set_window(next, flags).map_err(errno_of)
}

/// `LOOP_GET_STATUS64`: the device's current configuration.
///
/// `lo_number` and the flags are reported from the device rather than echoed
/// from whatever the caller last set, so a device whose read-only flag was
/// forced at bind time reports it. # C: O(1)
pub fn get_status(dev: &LoopDevice) -> Result<LoopInfo64, Errno> {
    let (window, flags, _) = dev.status().map_err(errno_of)?;
    Ok(LoopInfo64 {
        lo_number: dev.number(),
        lo_offset: window.offset,
        lo_sizelimit: window.sizelimit,
        lo_flags: flags,
        lo_file_name: window.file_name,
        ..LoopInfo64::default()
    })
}

/// `LOOP_SET_CAPACITY`: notice the backing file's size changing. # C: O(1)
pub fn set_capacity(dev: &LoopDevice) -> Result<u64, Errno> {
    dev.refresh_capacity().map_err(errno_of)
}

/// `LOOP_SET_BLOCK_SIZE`. Validated before it reaches the device, so an
/// illegal size cannot be stored and then read back. # C: O(1)
pub fn set_block_size(dev: &LoopDevice, bsize: u32) -> Result<(), Errno> {
    let bsize = validate_block_size(bsize)?;
    dev.set_block_size(bsize).map_err(errno_of)
}

/// `LOOP_SET_DIRECT_IO`.
///
/// Direct I/O is a property of how the backing description is read, and this
/// device always reads it the same way, so the flag is accepted only when it
/// asks for the behaviour already in force. Reporting success for a request
/// that changed nothing would tell a caller its I/O bypasses a cache it does
/// not. # C: O(1)
pub fn set_direct_io(_dev: &LoopDevice, enable: bool) -> Result<(), Errno> {
    if enable { Err(Errno::Einval) } else { Ok(()) }
}

/// Capacity in sectors a device would report for a backing file of
/// `file_bytes` through `window`. Exposed so a caller can size a device
/// before binding it. # C: O(1)
pub fn sectors_for(file_bytes: u64, window: &Window) -> u64 {
    capacity_sectors(file_bytes, window.offset, window.sizelimit)
}

#[cfg(test)]
#[path = "ioctl/tests.rs"]
mod tests;
