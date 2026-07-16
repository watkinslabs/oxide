use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use uaccess::MAX_RW_COUNT;

const MSGHDR_LEN: usize = 56;
const IOVEC_LEN: usize = 16;
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
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// Import a native Linux msghdr and complete iovec metadata array. # C: O(iovlen + faults)
pub(crate) fn import(msgp: u64) -> Result<RecvUser, i64> {
    let mut hdr = [0u8; MSGHDR_LEN];
    uaccess::copy_from_user(&mut hdr, msgp).map_err(errno)?;
    let name = u64_at(&hdr, 0);
    let namelen = u32_at(&hdr, 8);
    let iovp = u64_at(&hdr, 16);
    let iovlen = usize::try_from(u64_at(&hdr, 24)).map_err(|_| errno(Errno::Emsgsize))?;
    let control = u64_at(&hdr, 32);
    let controllen = usize::try_from(u64_at(&hdr, 40)).map_err(|_| errno(Errno::Einval))?;
    if iovlen > UIO_MAXIOV { return Err(errno(Errno::Emsgsize)); }
    import_iov_inner(msgp, name, namelen, control, controllen, iovp, iovlen)
}

fn import_iov_inner(msgp: u64, name: u64, namelen: u32, control: u64, controllen: usize, iovp: u64, iovlen: usize) -> Result<RecvUser, i64> {
    let bytes_len = iovlen.checked_mul(IOVEC_LEN).ok_or_else(|| errno(Errno::Emsgsize))?;
    let mut raw = vec![0u8; bytes_len];
    if bytes_len != 0 { uaccess::copy_from_user(&mut raw, iovp).map_err(errno)?; }
    let mut iov = Vec::with_capacity(iovlen);
    let mut capacity = 0usize;
    for entry in raw.chunks_exact(IOVEC_LEN) {
        let base = u64_at(entry, 0);
        let len = usize::try_from(u64_at(entry, 8)).map_err(|_| errno(Errno::Einval))?;
        if len != 0 && !uaccess::access_ok(base, len) { return Err(errno(Errno::Efault)); }
        capacity = core::cmp::min(MAX_RW_COUNT, capacity.saturating_add(len));
        iov.push(IoVec { base, len });
    }
    Ok(RecvUser { msgp, name, namelen, name_len_ptr: 0, control, controllen, iov, capacity })
}

/// Import a readv iovec array into the common receive destination shape. # C: O(iovlen + faults)
pub(crate) fn import_iov(iovp: u64, iovlen: usize) -> Result<RecvUser, i64> {
    if iovlen > UIO_MAXIOV { return Err(errno(Errno::Einval)); }
    import_iov_inner(0, 0, 0, 0, 0, iovp, iovlen)
}

/// Import a recvfrom payload and defer source-length access until delivery. # C: O(1)
pub(crate) fn import_recvfrom(base: u64, len: usize, name: u64,
    name_len_ptr: u64) -> RecvUser
{
    let capacity = core::cmp::min(MAX_RW_COUNT, len);
    RecvUser { msgp: 0, name, namelen: 0, name_len_ptr, control: 0,
        controllen: 0, iov: vec![IoVec { base, len: capacity }], capacity }
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
            if left != 0 { return if copied != 0 { Ok(copied) } else { Err(errno(Errno::Efault)) }; }
        }
        Ok(copied)
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

    /// Publish output controllen and flags after payload/address/ancillary handling. # C: O(faults)
    pub fn finish(&self, controllen: usize, flags: u32) -> Result<(), i64> {
        if self.msgp == 0 { return Ok(()); }
        uaccess::copy_to_user(self.msgp + 48, &flags.to_ne_bytes()).map_err(errno)?;
        uaccess::copy_to_user(self.msgp + 40, &(controllen as u64).to_ne_bytes()).map_err(errno)
    }

    /// Publish the true source address length. # C: O(faults)
    pub fn write_namelen(&self, len: u32) -> Result<(), i64> {
        if self.name_len_ptr != 0 {
            return uaccess::copy_to_user(self.name_len_ptr, &len.to_ne_bytes()).map_err(errno);
        }
        if self.msgp != 0 {
            return uaccess::copy_to_user(self.msgp + 8, &len.to_ne_bytes()).map_err(errno);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(iov: u64, iovlen: u64) -> [u8; MSGHDR_LEN] {
        let mut out = [0u8; MSGHDR_LEN];
        out[16..24].copy_from_slice(&iov.to_ne_bytes());
        out[24..32].copy_from_slice(&iovlen.to_ne_bytes());
        out
    }

    #[test]
    fn imports_all_iovecs_before_payload_copy() {
        let mut a = [0u8; 3];
        let mut b = [0u8; 2];
        let mut raw = [0u8; IOVEC_LEN * 2];
        raw[0..8].copy_from_slice(&(a.as_mut_ptr() as u64).to_ne_bytes());
        raw[8..16].copy_from_slice(&(a.len() as u64).to_ne_bytes());
        raw[16..24].copy_from_slice(&(b.as_mut_ptr() as u64).to_ne_bytes());
        raw[24..32].copy_from_slice(&(b.len() as u64).to_ne_bytes());
        let h = hdr(raw.as_ptr() as u64, 2);
        let imported = import(h.as_ptr() as u64).unwrap();
        assert_eq!(imported.capacity, 5);
        assert_eq!(imported.copy_payload(b"abcde"), Ok(5));
        assert_eq!(&a, b"abc");
        assert_eq!(&b, b"de");
    }

    #[test]
    fn copies_waitall_suffix_across_iovec_boundary() {
        let mut a = [0u8; 3];
        let mut b = [0u8; 3];
        let imported = RecvUser { msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: 0,
            controllen: 0, iov: vec![IoVec { base: a.as_mut_ptr() as u64, len: 3 },
                IoVec { base: b.as_mut_ptr() as u64, len: 3 }], capacity: 6 };
        assert_eq!(imported.copy_payload_at(0, b"ab"), Ok(2));
        assert_eq!(imported.copy_payload_at(2, b"cdef"), Ok(4));
        assert_eq!(&a, b"abc");
        assert_eq!(&b, b"def");
    }

    #[test]
    fn rejects_iov_count_with_linux_emsgsize() {
        let h = hdr(0, (UIO_MAXIOV + 1) as u64);
        assert_eq!(import(h.as_ptr() as u64).err(), Some(errno(Errno::Emsgsize)));
    }

    #[test]
    fn recvfrom_defers_payload_fault_until_copy() {
        let user = import_recvfrom(1, 4, 0, 0);
        assert_eq!(user.capacity, 4);
        assert_eq!(user.iov, vec![IoVec { base: 1, len: 4 }]);
        assert_eq!(user.validate_payload_range(), Ok(()));
    }

    #[test]
    fn recvfrom_rejects_out_of_range_payload_before_receive() {
        let user = import_recvfrom(u64::MAX, 0, 0, 0);
        assert_eq!(user.validate_payload_range(), Err(errno(Errno::Efault)));
    }

    #[test]
    fn recvfrom_source_length_is_late_and_reports_true_size() {
        let mut addr = [0xa5u8; 2];
        let mut len = 2i32;
        let user = import_recvfrom(0, 0, addr.as_mut_ptr() as u64,
            (&mut len as *mut i32) as u64);
        assert_eq!(user.copy_name(b"abcd"), Ok(()));
        assert_eq!(addr, *b"ab");
        assert_eq!(len, 4);
    }

    #[test]
    fn recvfrom_negative_source_length_fails_after_payload_phase() {
        let mut addr = [0xa5u8; 4];
        let mut len = -1i32;
        let user = import_recvfrom(0, 0, addr.as_mut_ptr() as u64,
            (&mut len as *mut i32) as u64);
        assert_eq!(user.copy_name(b"abcd"), Err(errno(Errno::Einval)));
        assert_eq!(addr, [0xa5; 4]);
        assert_eq!(len, -1);
    }

    #[test]
    fn recvfrom_null_source_ignores_length_pointer() {
        let user = import_recvfrom(0, 0, 0, 1);
        assert_eq!(user.copy_name(b"abcd"), Ok(()));
    }

    #[test]
    fn recvfrom_nonnull_source_requires_length_pointer_late() {
        let mut addr = [0xa5u8; 4];
        let user = import_recvfrom(0, 0, addr.as_mut_ptr() as u64, 0);
        assert_eq!(user.copy_name(b"abcd"), Err(errno(Errno::Efault)));
        assert_eq!(addr, [0xa5; 4]);
    }

    #[test]
    fn null_name_leaves_namelen_untouched() {
        let mut h = [0u8; MSGHDR_LEN];
        h[8..12].copy_from_slice(&77u32.to_ne_bytes());
        let user = RecvUser { msgp: h.as_mut_ptr() as u64, name: 0, namelen: 77, name_len_ptr: 0,
            control: 0, controllen: 0, iov: Vec::new(), capacity: 0 };
        assert_eq!(user.copy_name(b"ignored"), Ok(()));
        assert_eq!(u32_at(&h, 8), 77);
    }
}
