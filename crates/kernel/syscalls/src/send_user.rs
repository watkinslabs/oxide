use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use uaccess::MAX_RW_COUNT;

const MSGHDR_LEN: usize = 56;
const IOVEC_LEN: usize = 16;
const UIO_MAXIOV: usize = 1024;
const SOCKADDR_STORAGE_LEN: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IoVec {
    base: u64,
    len: usize,
}

pub(crate) struct SendUser {
    pub payload: Vec<u8>,
    pub payload_faulted: bool,
    pub control: Vec<u8>,
    pub name: Vec<u8>,
}

struct SendMeta {
    iov: Vec<IoVec>,
    control: u64,
    controllen: usize,
    name: Vec<u8>,
}

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn copy_vec(src: u64, len: usize) -> Result<Vec<u8>, i64> {
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| errno(Errno::Enomem))?;
    out.resize(len, 0);
    if len != 0 { uaccess::copy_from_user(&mut out, src).map_err(errno)?; }
    Ok(out)
}

fn gather_with<F>(iov: &[IoVec], total: usize, mut copy: F) -> Result<(Vec<u8>, bool), i64>
where F: FnMut(*mut u8, u64, usize) -> usize {
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| errno(Errno::Enomem))?;
    out.resize(total, 0);
    let mut copied = 0usize;
    for entry in iov {
        if copied == total { break; }
        let take = core::cmp::min(entry.len, total - copied);
        if take == 0 { continue; }
        // SAFETY: copied is bounded by the initialized allocation's total length.
        let dst = unsafe { out.as_mut_ptr().add(copied) };
        let left = core::cmp::min(take, copy(dst, entry.base, take));
        copied += take - left;
        if left != 0 {
            out.truncate(copied);
            return if copied != 0 { Ok((out, true)) } else { Err(errno(Errno::Efault)) };
        }
    }
    out.truncate(copied);
    Ok((out, false))
}

fn gather(iov: &[IoVec], total: usize) -> Result<(Vec<u8>, bool), i64> {
    gather_with(iov, total, |dst, src, len| {
        // SAFETY: dst spans initialized Vec storage; raw usercopy recovers source faults.
        unsafe { uaccess::raw_copy_from_user(dst, src, len) }
    })
}

fn capped_total(iov: &[IoVec]) -> usize {
    let mut total = 0usize;
    for entry in iov {
        total = core::cmp::min(MAX_RW_COUNT, total.saturating_add(entry.len));
    }
    total
}

fn import_meta(msgp: u64) -> Result<SendMeta, i64> {
    let mut hdr = [0u8; MSGHDR_LEN];
    uaccess::copy_from_user(&mut hdr, msgp).map_err(errno)?;
    let name = u64_at(&hdr, 0);
    let namelen = u32_at(&hdr, 8) as usize;
    let iovp = u64_at(&hdr, 16);
    let iovlen = usize::try_from(u64_at(&hdr, 24)).map_err(|_| errno(Errno::Emsgsize))?;
    let control = u64_at(&hdr, 32);
    let controllen = usize::try_from(u64_at(&hdr, 40)).map_err(|_| errno(Errno::Einval))?;
    if iovlen > UIO_MAXIOV { return Err(errno(Errno::Emsgsize)); }
    if namelen > SOCKADDR_STORAGE_LEN { return Err(errno(Errno::Einval)); }
    if controllen > net::sysctl::optmem_max() { return Err(errno(Errno::Enobufs)); }

    let bytes_len = iovlen.checked_mul(IOVEC_LEN).ok_or_else(|| errno(Errno::Emsgsize))?;
    let raw = copy_vec(iovp, bytes_len)?;
    let mut iov = Vec::with_capacity(iovlen);
    for entry in raw.chunks_exact(IOVEC_LEN) {
        let base = u64_at(entry, 0);
        let len = usize::try_from(u64_at(entry, 8)).map_err(|_| errno(Errno::Einval))?;
        if len != 0 && !uaccess::access_ok(base, len) { return Err(errno(Errno::Efault)); }
        iov.push(IoVec { base, len });
    }

    let name = copy_vec(name, namelen)?;
    Ok(SendMeta { iov, control, controllen, name })
}

/// Validate the send envelope and ancillary bytes without touching payload pages. # C: O(iovlen + name + control)
pub(crate) fn import_raw_oob(msgp: u64) -> Result<(), i64> {
    let meta = import_meta(msgp)?;
    copy_vec(meta.control, meta.controllen).map(|_| ())
}

/// Import a native LP64 Linux msghdr, iovecs, and send-side byte buffers. # C: O(iovlen + bytes + faults)
pub(crate) fn import(msgp: u64) -> Result<SendUser, i64> {
    let meta = import_meta(msgp)?;
    let (payload, payload_faulted) = gather(&meta.iov, capped_total(&meta.iov))?;
    let control = copy_vec(meta.control, meta.controllen)?;
    Ok(SendUser { payload, payload_faulted, control, name: meta.name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(out: &mut [u8], at: usize, value: u32) {
        out[at..at + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn put_u64(out: &mut [u8], at: usize, value: u64) {
        out[at..at + 8].copy_from_slice(&value.to_ne_bytes());
    }

    fn header(name: &[u8], control: &[u8], iovp: u64, iovlen: u64) -> [u8; MSGHDR_LEN] {
        let mut out = [0u8; MSGHDR_LEN];
        put_u64(&mut out, 0, name.as_ptr() as u64);
        put_u32(&mut out, 8, name.len() as u32);
        put_u64(&mut out, 16, iovp);
        put_u64(&mut out, 24, iovlen);
        put_u64(&mut out, 32, control.as_ptr() as u64);
        put_u64(&mut out, 40, control.len() as u64);
        out
    }

    fn iovec(out: &mut [u8], at: usize, bytes: &[u8]) {
        put_u64(out, at, bytes.as_ptr() as u64);
        put_u64(out, at + 8, bytes.len() as u64);
    }

    #[test]
    fn imports_unaligned_header_and_complete_unaligned_iovec_array() {
        let a = b"abc";
        let b = b"de";
        let mut raw = [0u8; IOVEC_LEN * 2 + 1];
        iovec(&mut raw, 1, a);
        iovec(&mut raw, 1 + IOVEC_LEN, b);
        let h = header(&[], &[], raw[1..].as_ptr() as u64, 2);
        let mut unaligned = [0u8; MSGHDR_LEN + 1];
        unaligned[1..].copy_from_slice(&h);

        let imported = import(unaligned[1..].as_ptr() as u64).unwrap();
        assert_eq!(imported.payload, b"abcde");
    }

    #[test]
    fn rejects_iov_count_with_linux_emsgsize() {
        let h = header(&[], &[], 0, (UIO_MAXIOV + 1) as u64);
        assert_eq!(import(h.as_ptr() as u64).err(), Some(errno(Errno::Emsgsize)));
    }

    #[test]
    fn caps_saturating_iovec_total_at_max_rw_count() {
        let iov = [IoVec { base: 1, len: MAX_RW_COUNT - 1 },
            IoVec { base: 1, len: usize::MAX }];
        assert_eq!(capped_total(&iov), MAX_RW_COUNT);
    }

    #[test]
    fn payload_fault_returns_prefix_or_efault() {
        let iov = [IoVec { base: 10, len: 4 }, IoVec { base: 20, len: 3 }];
        let (copied, faulted) = gather_with(&iov, 7, |dst, src, len| {
            let bytes = if src == 10 { b"abcd".as_slice() } else { b"xy".as_slice() };
            let n = core::cmp::min(len, bytes.len());
            // SAFETY: gather_with provides n writable bytes and bytes contains n readable bytes.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, n); }
            len - n
        }).unwrap();
        assert_eq!(copied, b"abcdxy");
        assert!(faulted);

        assert_eq!(gather_with(&iov, 7, |_dst, _src, len| len).err(),
            Some(errno(Errno::Efault)));
    }

    #[test]
    fn copies_payload_control_and_name_into_kernel_vecs() {
        let a = b"payload ";
        let b = b"bytes";
        let name = b"sockaddr";
        let control = b"ancillary";
        let mut raw = [0u8; IOVEC_LEN * 2];
        iovec(&mut raw, 0, a);
        iovec(&mut raw, IOVEC_LEN, b);
        let h = header(name, control, raw.as_ptr() as u64, 2);

        let imported = import(h.as_ptr() as u64).unwrap();
        assert_eq!(imported.payload, b"payload bytes");
        assert_eq!(imported.control, control);
        assert_eq!(imported.name, name);
    }
}
