//! SG_IO on shared `sd*` block devices.

extern crate alloc;

use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::{File, Fmode};

const SG_IOVEC_BYTES: usize = 16;

#[derive(Copy, Clone)]
struct UserIovec { base: u64, len: usize }

/// Route Linux SCSI-generic v3 `SG_IO` only to a disk published by the shared
/// SCSI mid-layer.  A native block endpoint wrapped for ordinary `sd*` I/O
/// remains block-only until it supplies a true raw-CDB transport. # C: O(data)
pub(super) fn handle_scsi_ioctl(file: &File, req: u64, arg: u64, raw_io: bool) -> Option<i64> {
    if req != ::scsi::SG_IO { return None; }
    let dev_t = vfs::device_inode_devt(&file.inode())?.raw();
    let target = ::scsi::sg_target(dev_t)?;
    Some(sg_io(target, file.f_mode().contains(Fmode::WRITE), arg, raw_io))
}

fn sg_io(target: ::scsi::SgIoTarget, open_for_write: bool, arg: u64, raw_io: bool) -> i64 {
    let mut wire = [0u8; ::scsi::SG_IO_HDR_BYTES];
    if uaccess::copy_from_user(&mut wire, arg).is_err() { return err(Errno::Efault); }
    let mut hdr = ::scsi::SgHeader::from_bytes(wire);
    if !hdr.has_interface_id() { return put_header(arg, &hdr, err(Errno::Einval)); }
    let Some(max_transfer) = target.max_transfer_bytes() else { return put_header(arg, &hdr, err(Errno::Eopnotsupp)); };
    let requested = hdr.dxfer_len() as usize;
    if requested > max_transfer { return put_header(arg, &hdr, err(Errno::Eio)); }
    if hdr.cmd_len() < 6 { return put_header(arg, &hdr, err(Errno::Emsgsize)); }
    if hdr.cmd_len() as usize > ::scsi::MAX_CDB_BYTES || hdr.cmd_len() as usize > target.max_cdb_bytes() {
        return put_header(arg, &hdr, err(Errno::Einval));
    }

    let mut cdb = [0u8; ::scsi::MAX_CDB_BYTES];
    if uaccess::copy_from_user(&mut cdb[..hdr.cmd_len() as usize], hdr.cmdp()).is_err() { return err(Errno::Efault); }
    let command = match ::scsi::Command::new(&cdb[..hdr.cmd_len() as usize]) {
        Ok(command) => command,
        Err(_) => return put_header(arg, &hdr, err(Errno::Einval)),
    };
    if !::scsi::command_allowed(&command, open_for_write, raw_io) { return put_header(arg, &hdr, err(Errno::Eperm)); }
    let direction = if requested == 0 { ::scsi::DataDirection::None } else {
        match hdr.direction() { Some(direction) => direction, None => return put_header(arg, &hdr, err(Errno::Einval)) }
    };

    let (iovecs, mapped) = match iovecs(&hdr) { Ok(iovecs) => iovecs, Err(rv) => return rv };
    let mut data = match allocate(mapped) { Ok(data) => data, Err(rv) => return rv };
    // Linux treats SG_DXFER_TO_FROM_DEV as a read-direction request, but its
    // indirect buffer is copied in before submission as well.
    if direction == ::scsi::DataDirection::ToDevice || hdr.direction_raw() == -4 {
        if copy_from_iovecs(&mut data, &iovecs).is_err() { return err(Errno::Efault); }
    }
    let start_ns = timekeeper::monotonic_ns();
    let completion = match target.execute(&command, &mut data, direction, hdr.timeout_ms()) {
        Ok(completion) => completion,
        Err(error) => return put_header(arg, &hdr, block_err(error)),
    };
    let duration_ms = timekeeper::monotonic_ns().saturating_sub(start_ns).saturating_div(1_000_000).min(u64::from(u32::MAX)) as u32;

    let sense = completion.sense();
    let sense_len = core::cmp::min(usize::from(hdr.mx_sb_len()), sense.len());
    if sense_len != 0 && hdr.sbp() != 0 && uaccess::copy_to_user(hdr.sbp(), &sense[..sense_len]).is_err() {
        return err(Errno::Efault);
    }
    let sense_written = if sense_len != 0 && hdr.sbp() != 0 { sense_len as u8 } else { 0 };
    if direction == ::scsi::DataDirection::FromDevice {
        let transferred = mapped.saturating_sub(core::cmp::min(mapped, completion.resid() as usize));
        if copy_to_iovecs(&data[..transferred], &iovecs).is_err() { return err(Errno::Efault); }
    }
    hdr.complete(completion, (requested - mapped) as u32, sense_written, duration_ms);
    put_header(arg, &hdr, 0)
}

fn iovecs(hdr: &::scsi::SgHeader) -> Result<(Vec<UserIovec>, usize), i64> {
    let requested = hdr.dxfer_len() as usize;
    if requested == 0 { return Ok((Vec::new(), 0)); }
    if hdr.iovec_count() == 0 { return Ok((alloc::vec![UserIovec { base: hdr.dxferp(), len: requested }], requested)); }
    let count = hdr.iovec_count() as usize;
    let table_bytes = count.checked_mul(SG_IOVEC_BYTES).ok_or_else(|| err(Errno::Einval))?;
    let mut table = allocate(table_bytes)?;
    if uaccess::copy_from_user(&mut table, hdr.dxferp()).is_err() { return Err(err(Errno::Efault)); }
    let mut out = Vec::new();
    if out.try_reserve_exact(count).is_err() { return Err(err(Errno::Enomem)); }
    let mut remaining = requested;
    for bytes in table.chunks_exact(SG_IOVEC_BYTES) {
        if remaining == 0 { break; }
        let base = u64::from_ne_bytes(bytes[0..8].try_into().expect("iovec base"));
        let len = usize::try_from(u64::from_ne_bytes(bytes[8..16].try_into().expect("iovec len"))).unwrap_or(usize::MAX);
        let take = core::cmp::min(remaining, len);
        if take != 0 { out.push(UserIovec { base, len: take }); }
        remaining -= take;
    }
    Ok((out, requested - remaining))
}

fn allocate(len: usize) -> Result<Vec<u8>, i64> {
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(len).is_err() { return Err(err(Errno::Enomem)); }
    bytes.resize(len, 0);
    Ok(bytes)
}

fn copy_from_iovecs(dst: &mut [u8], iovecs: &[UserIovec]) -> Result<(), ()> {
    let mut offset: usize = 0;
    for iov in iovecs {
        let end = offset.checked_add(iov.len).ok_or(())?;
        uaccess::copy_from_user(&mut dst[offset..end], iov.base).map_err(|_| ())?;
        offset = end;
    }
    (offset == dst.len()).then_some(()).ok_or(())
}

fn copy_to_iovecs(src: &[u8], iovecs: &[UserIovec]) -> Result<(), ()> {
    let mut offset: usize = 0;
    for iov in iovecs {
        if offset == src.len() { break; }
        let take = core::cmp::min(iov.len, src.len() - offset);
        uaccess::copy_to_user(iov.base, &src[offset..offset + take]).map_err(|_| ())?;
        offset += take;
    }
    (offset == src.len()).then_some(()).ok_or(())
}

fn put_header(arg: u64, hdr: &::scsi::SgHeader, result: i64) -> i64 {
    if uaccess::copy_to_user(arg, hdr.bytes()).is_err() { err(Errno::Efault) } else { result }
}

fn block_err(error: block::BlockError) -> i64 {
    match error {
        block::BlockError::Eio => err(Errno::Eio),
        block::BlockError::Enxio => err(Errno::Enxio),
        block::BlockError::Eagain => err(Errno::Eagain),
        block::BlockError::Enomem => err(Errno::Enomem),
        block::BlockError::Ebusy => err(Errno::Ebusy),
        block::BlockError::Einval => err(Errno::Einval),
        block::BlockError::Enospc => err(Errno::Enospc),
        block::BlockError::Erofs => err(Errno::Erofs),
        block::BlockError::Eopnotsupp => err(Errno::Eopnotsupp),
        block::BlockError::Eoverflow => err(Errno::Eoverflow),
        block::BlockError::Etoomanyrefs => err(Errno::Etoomanyrefs),
    }
}

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }
