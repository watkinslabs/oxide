use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use uaccess::MAX_RW_COUNT;

use crate::msg_layout::{MsgLayout, entry::published_flags};

/// Largest `msghdr` either ABI presents, so one stack buffer serves both.
const MSGHDR_MAX: usize = 56;
/// `sizeof(struct sockaddr_storage)` — Linux `__copy_msghdr` clamps an
/// oversized `msg_namelen` to this before the receive.
const SOCKADDR_STORAGE_LEN: u32 = 128;
const UIO_MAXIOV: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IoVec {
    pub base: u64,
    pub len: usize,
}

pub(crate) struct RecvUser {
    pub msgp: u64,
    pub name: u64,
    pub namelen: u32,
    pub name_len_ptr: u64,
    pub control: u64,
    pub controllen: usize,
    pub iov: Vec<IoVec>,
    pub capacity: usize,
    /// The shape `msgp` and the control stream are written back in, decided
    /// once by the entry (`crate::msg_layout`) and never re-derived here.
    pub layout: MsgLayout,
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Import one Linux msghdr and its complete iovec metadata array, in the
/// layout the entry decided. # C: O(iovlen + faults)
pub(crate) fn import(msgp: u64, layout: MsgLayout) -> Result<RecvUser, i64> {
    let mut raw_hdr = [0u8; MSGHDR_MAX];
    let hdr = &mut raw_hdr[..layout.msghdr_size()];
    uaccess::copy_from_user(hdr, msgp).map_err(errno)?;
    let at = layout.msghdr();
    let name = layout.word_at(hdr, at.name);
    // Linux `__copy_msghdr`: when a name buffer is supplied, a negative
    // `msg_namelen` is EINVAL (before any receive) and an oversized one is
    // clamped to `sockaddr_storage`. Without the buffer the length is unused.
    // (The recvfrom path validates its own value-result pointer in `copy_name`.)
    let namelen = layout.u32_at(hdr, at.namelen);
    let namelen = if name != 0 {
        if (namelen as i32) < 0 { return Err(errno(Errno::Einval)); }
        namelen.min(SOCKADDR_STORAGE_LEN)
    } else { namelen };
    let iovp = layout.word_at(hdr, at.iov);
    let iovlen = usize::try_from(layout.word_at(hdr, at.iovlen))
        .map_err(|_| errno(Errno::Emsgsize))?;
    let control = layout.word_at(hdr, at.control);
    let controllen = usize::try_from(layout.word_at(hdr, at.controllen))
        .map_err(|_| errno(Errno::Einval))?;
    if iovlen > UIO_MAXIOV { return Err(errno(Errno::Emsgsize)); }
    import_iov_inner(msgp, name, namelen, control, controllen, iovp, iovlen, layout)
}

fn import_iov_inner(msgp: u64, name: u64, namelen: u32, control: u64, controllen: usize,
    iovp: u64, iovlen: usize, layout: MsgLayout) -> Result<RecvUser, i64>
{
    let stride = layout.iovec_size();
    let bytes_len = iovlen.checked_mul(stride).ok_or_else(|| errno(Errno::Emsgsize))?;
    let mut raw = vec![0u8; bytes_len];
    if bytes_len != 0 { uaccess::copy_from_user(&mut raw, iovp).map_err(errno)?; }
    let mut iov = Vec::with_capacity(iovlen);
    let mut capacity = 0usize;
    for entry in raw.chunks_exact(stride) {
        let base = layout.word_at(entry, 0);
        let len = usize::try_from(layout.word_at(entry, layout.word()))
            .map_err(|_| errno(Errno::Einval))?;
        if len != 0 && !uaccess::access_ok(base, len) { return Err(errno(Errno::Efault)); }
        capacity = core::cmp::min(MAX_RW_COUNT, capacity.saturating_add(len));
        iov.push(IoVec { base, len });
    }
    Ok(RecvUser { msgp, name, namelen, name_len_ptr: 0, control, controllen, iov, capacity,
        layout })
}

/// Import a readv iovec array into the common receive destination shape. # C: O(iovlen + faults)
pub(crate) fn import_iov(iovp: u64, iovlen: usize) -> Result<RecvUser, i64> {
    if iovlen > UIO_MAXIOV { return Err(errno(Errno::Einval)); }
    import_iov_inner(0, 0, 0, 0, 0, iovp, iovlen, MsgLayout::Native)
}

/// Import a recvfrom payload and defer source-length access until delivery. # C: O(1)
pub(crate) fn import_recvfrom(base: u64, len: usize, name: u64,
    name_len_ptr: u64) -> RecvUser
{
    let capacity = core::cmp::min(MAX_RW_COUNT, len);
    RecvUser { msgp: 0, name, namelen: 0, name_len_ptr, control: 0,
        controllen: 0, iov: vec![IoVec { base, len: capacity }], capacity,
        layout: MsgLayout::Native }
}

impl RecvUser {
    /// Validate imported payload ranges without touching their pages. # C: O(iov)
    pub fn validate_payload_range(&self) -> Result<(), i64> {
        for iov in &self.iov {
            if !uaccess::access_ok(iov.base, iov.len) { return Err(errno(Errno::Efault)); }
        }
        Ok(())
    }

    /// Scatter payload, returning copied prefix or EFAULT when no byte lands. # C: O(iov + bytes)
    pub fn copy_payload(&self, payload: &[u8]) -> Result<usize, i64> {
        self.copy_payload_at(0, payload)
    }

    /// Scatter payload after `offset` bytes already copied by this receive. # C: O(iov + bytes)
    pub fn copy_payload_at(&self, offset: usize, payload: &[u8]) -> Result<usize, i64> {
        let (copied, faulted) = self.scatter(offset, payload);
        if faulted && copied == 0 { return Err(errno(Errno::Efault)); }
        Ok(copied)
    }

    /// Copy one queued fragment the way a stream transport consumes it: all of
    /// it, or none of it. A destination fault reports EFAULT however much of
    /// the fragment reached user memory, so the transport retires nothing and
    /// the receive answers with whatever earlier fragments delivered. A copy
    /// cut short because the caller's buffer ran out is not a fault and
    /// reports what fit. # C: O(iov + bytes)
    pub fn copy_payload_fragment(&self, offset: usize, payload: &[u8]) -> Result<usize, i64> {
        let (copied, faulted) = self.scatter(offset, payload);
        if faulted { return Err(errno(Errno::Efault)); }
        Ok(copied)
    }

    /// Bytes placed, and whether the destination faulted. A short copy with no
    /// fault means the caller's buffer ran out. # C: O(iov + bytes)
    fn scatter(&self, offset: usize, payload: &[u8]) -> (usize, bool) {
        let mut copied = 0usize;
        let mut skip = offset;
        for iov in &self.iov {
            if skip >= iov.len { skip -= iov.len; continue; }
            if copied == payload.len() { break; }
            let at = skip;
            skip = 0;
            let take = core::cmp::min(iov.len - at, payload.len() - copied);
            if take == 0 { continue; }
            // SAFETY: payload suffix is readable; raw usercopy recovers destination faults.
            let left = unsafe { uaccess::raw_copy_to_user(iov.base + at as u64, payload[copied..].as_ptr(), take) };
            copied += take - left;
            if left != 0 { return (copied, true); }
        }
        (copied, false)
    }

    /// Scatter one record atomically from the receiver's point of view.
    /// A short raw usercopy is reported as EFAULT even if a prefix landed;
    /// record transports must retire that record rather than re-expose it.
    /// # C: O(iov + bytes)
    pub fn copy_payload_record(&self, payload: &[u8]) -> Result<usize, i64> {
        let (copied, _) = self.scatter(0, payload);
        if copied == payload.len() { return Ok(copied); }
        crate::recv_txn::record_result(copied, errno(Errno::Efault))
    }

    /// Copy a source sockaddr using imported msg_namelen and publish its true length. # C: O(bytes + faults)
    pub fn copy_name(&self, sa: &[u8]) -> Result<(), i64> {
        if self.name == 0 { return Ok(()); }
        if self.msgp == 0 && self.name_len_ptr == 0 { return Err(errno(Errno::Efault)); }
        let capacity = if self.name_len_ptr == 0 {
            self.namelen as usize
        } else {
            let mut raw = [0u8; 4];
            uaccess::copy_from_user(&mut raw, self.name_len_ptr).map_err(errno)?;
            let len = i32::from_ne_bytes(raw);
            if len < 0 { return Err(errno(Errno::Einval)); }
            len as usize
        };
        let take = core::cmp::min(capacity, sa.len());
        self.write_namelen(sa.len() as u32)?;
        uaccess::copy_to_user(self.name, &sa[..take]).map_err(errno)
    }

    /// Publish output controllen and flags after payload/address/ancillary
    /// handling. `MSG_CMSG_COMPAT` is kernel bookkeeping: it records which
    /// layout the call speaks and is stripped before the caller sees
    /// `msg_flags`. # C: O(faults)
    pub fn finish(&self, controllen: usize, flags: u32) -> Result<(), i64> {
        if self.msgp == 0 { return Ok(()); }
        let at = self.layout.msghdr();
        uaccess::copy_to_user(self.msgp + at.flags as u64,
            &published_flags(flags).to_ne_bytes()).map_err(errno)?;
        let word = self.layout.word();
        uaccess::copy_to_user(self.msgp + at.controllen as u64,
            &self.layout.word_bytes(controllen as u64)[..word]).map_err(errno)
    }

    /// Publish the true source address length. # C: O(faults)
    pub fn write_namelen(&self, len: u32) -> Result<(), i64> {
        if self.name_len_ptr != 0 {
            return uaccess::copy_to_user(self.name_len_ptr, &len.to_ne_bytes()).map_err(errno);
        }
        if self.msgp != 0 {
            let at = self.layout.msghdr().namelen as u64;
            return uaccess::copy_to_user(self.msgp + at, &len.to_ne_bytes()).map_err(errno);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "recv_user/tests.rs"]
mod tests;
