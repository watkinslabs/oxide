// Every caller-memory access the ioctl stage makes goes through `uaccess`.
//
// A range check answers "could this address be user memory"; it does NOT make
// the dereference recoverable. Only the hand-written usercopy routine carries
// `__ex_table` fixups, so a plain compiler-emitted load/store on a user address
// that faults — the caller unmapped the page under the syscall — takes the
// kernel down instead of answering EFAULT. These helpers are the ioctl stage's
// only permitted way to touch a caller address.

use syscall::errno::Errno;

/// `-EFAULT` in the i64 form every ioctl arm returns.
pub(crate) const EFAULT: i64 = -(Errno::Efault.as_i32() as i64);

/// Fetch a fixed-size caller payload. # C: O(N)
pub(crate) fn get_bytes<const N: usize>(addr: u64) -> Result<[u8; N], i64> {
    let mut buf = [0u8; N];
    uaccess::copy_from_user(&mut buf, addr).map_err(|_| EFAULT)?;
    Ok(buf)
}

/// Fetch a run-length caller payload into `dst`. # C: O(dst.len())
pub(crate) fn get_into(addr: u64, dst: &mut [u8]) -> Result<(), i64> {
    uaccess::copy_from_user(dst, addr).map_err(|_| EFAULT)
}

/// Store a caller payload. # C: O(src.len())
pub(crate) fn put_bytes(addr: u64, src: &[u8]) -> Result<(), i64> {
    uaccess::copy_to_user(addr, src).map_err(|_| EFAULT)
}

/// # C: O(1)
pub(crate) fn get_u8(addr: u64) -> Result<u8, i64> { Ok(get_bytes::<1>(addr)?[0]) }

/// # C: O(1)
pub(crate) fn get_u16(addr: u64) -> Result<u16, i64> { Ok(u16::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn get_u32(addr: u64) -> Result<u32, i64> { Ok(u32::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn get_i32(addr: u64) -> Result<i32, i64> { Ok(i32::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn put_u8(addr: u64, v: u8) -> Result<(), i64> { put_bytes(addr, &[v]) }

/// # C: O(1)
pub(crate) fn put_u16(addr: u64, v: u16) -> Result<(), i64> { put_bytes(addr, &v.to_ne_bytes()) }

/// # C: O(1)
pub(crate) fn put_u32(addr: u64, v: u32) -> Result<(), i64> { put_bytes(addr, &v.to_ne_bytes()) }

/// # C: O(1)
pub(crate) fn put_u64(addr: u64, v: u64) -> Result<(), i64> { put_bytes(addr, &v.to_ne_bytes()) }

/// # C: O(1)
pub(crate) fn put_i32(addr: u64, v: i32) -> Result<(), i64> { put_bytes(addr, &v.to_ne_bytes()) }

/// # C: O(1)
pub(crate) fn put_i64(addr: u64, v: i64) -> Result<(), i64> { put_bytes(addr, &v.to_ne_bytes()) }
