// Every caller-memory access a syscall slot makes goes through `uaccess`.
//
// A range check answers "could this address be user memory"; it does NOT make
// the dereference recoverable. Only the hand-written usercopy routine carries
// `__ex_table` fixups, so a plain compiler-emitted load/store on a user address
// that faults — the caller unmapped the page under the syscall — takes the
// kernel down instead of answering EFAULT. These helpers are a slot file's
// only permitted way to touch a caller address.
//
// `ioctl_user::copy` is the same contract in the ioctl stage's `i64` return
// flavour; this one answers `Errno` because that is what the slot files and
// their shared helpers propagate.

use syscall::errno::Errno;

/// `-EFAULT` in the i64 form a slot returns directly.
pub(crate) const EFAULT: i64 = -(Errno::Efault.as_i32() as i64);

/// Fetch a fixed-size caller payload. # C: O(N)
pub(crate) fn get_bytes<const N: usize>(addr: u64) -> Result<[u8; N], Errno> {
    let mut buf = [0u8; N];
    uaccess::copy_from_user(&mut buf, addr)?;
    Ok(buf)
}

/// Fetch a run-length caller payload into `dst`. # C: O(dst.len())
pub(crate) fn get_into(addr: u64, dst: &mut [u8]) -> Result<(), Errno> {
    uaccess::copy_from_user(dst, addr)
}

/// Store a caller payload. # C: O(src.len())
pub(crate) fn put_bytes(addr: u64, src: &[u8]) -> Result<(), Errno> {
    uaccess::copy_to_user(addr, src)
}

/// # C: O(1)
pub(crate) fn get_u8(addr: u64) -> Result<u8, Errno> { Ok(get_bytes::<1>(addr)?[0]) }

/// # C: O(1)
pub(crate) fn get_i8(addr: u64) -> Result<i8, Errno> { Ok(get_bytes::<1>(addr)?[0] as i8) }

/// # C: O(1)
pub(crate) fn get_u16(addr: u64) -> Result<u16, Errno> { Ok(u16::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn get_i16(addr: u64) -> Result<i16, Errno> { Ok(i16::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn get_u32(addr: u64) -> Result<u32, Errno> { Ok(u32::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn get_i32(addr: u64) -> Result<i32, Errno> { Ok(i32::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn get_u64(addr: u64) -> Result<u64, Errno> { Ok(u64::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn get_i64(addr: u64) -> Result<i64, Errno> { Ok(i64::from_ne_bytes(get_bytes(addr)?)) }

/// # C: O(1)
pub(crate) fn put_u8(addr: u64, v: u8) -> Result<(), Errno> { put_bytes(addr, &[v]) }

/// # C: O(1)
pub(crate) fn put_i16(addr: u64, v: i16) -> Result<(), Errno> { put_bytes(addr, &v.to_ne_bytes()) }

/// # C: O(1)
pub(crate) fn put_u32(addr: u64, v: u32) -> Result<(), Errno> { put_bytes(addr, &v.to_ne_bytes()) }

/// # C: O(1)
pub(crate) fn put_i32(addr: u64, v: i32) -> Result<(), Errno> { put_bytes(addr, &v.to_ne_bytes()) }

/// # C: O(1)
pub(crate) fn put_u64(addr: u64, v: u64) -> Result<(), Errno> { put_bytes(addr, &v.to_ne_bytes()) }

/// # C: O(1)
pub(crate) fn put_i64(addr: u64, v: i64) -> Result<(), Errno> { put_bytes(addr, &v.to_ne_bytes()) }
