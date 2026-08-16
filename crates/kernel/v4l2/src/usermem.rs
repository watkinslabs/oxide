//! The caller's memory, as the ioctl surface sees it.
//!
//! Every V4L2 command's primary argument is copied in whole, worked on as
//! bytes, and copied back — the reference's `video_usercopy` shape. That keeps
//! the dispatch a pure function of a byte buffer, which is why the ioctl
//! contract is testable without a running kernel.
//!
//! A few commands additionally follow a pointer the caller embedded in that
//! buffer (the extended-control array, the per-plane array of a multi-planar
//! buffer). Those go through [`UserMem`], so the same dispatch code runs
//! against real user memory in the kernel and against a plain map in a test.

use syscall::errno::Errno;

/// Access to the calling process's address space for the pointers a V4L2
/// argument embeds.
pub trait UserMem {
    /// Copy `dst.len()` bytes from user address `addr`. # C: O(dst.len)
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Errno>;
    /// Copy `src` to user address `addr`. # C: O(src.len)
    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Errno>;
}

/// A [`UserMem`] that refuses every access, for the commands that embed no
/// pointer and for tests asserting a command does not follow one.
pub struct NoUserMem;

impl UserMem for NoUserMem {
    /// # C: O(1)
    fn read(&self, _addr: u64, _dst: &mut [u8]) -> Result<(), Errno> { Err(Errno::Efault) }
    /// # C: O(1)
    fn write(&self, _addr: u64, _src: &[u8]) -> Result<(), Errno> { Err(Errno::Efault) }
}

/// Largest V4L2 argument, so one stack buffer serves every command.
/// `v4l2_create_buffers` is the biggest at 256 bytes.
pub const MAX_ARG_BYTES: usize = 256;

/// Read a 32-bit field at `off`, or zero when the buffer is too short. A short
/// buffer cannot happen for a command whose declared size the dispatch already
/// checked; returning zero rather than panicking keeps the accessor total.
/// # C: O(1)
pub fn r32(b: &[u8], off: usize) -> u32 {
    if off + 4 > b.len() { return 0; }
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Signed reading of the same word. # C: O(1)
pub fn r32i(b: &[u8], off: usize) -> i32 { r32(b, off) as i32 }

/// Read a 64-bit field at `off`. # C: O(1)
pub fn r64(b: &[u8], off: usize) -> u64 {
    if off + 8 > b.len() { return 0; }
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Signed reading of the same doubleword. # C: O(1)
pub fn r64i(b: &[u8], off: usize) -> i64 { r64(b, off) as i64 }

/// Read a single byte field. # C: O(1)
pub fn r8(b: &[u8], off: usize) -> u8 { if off < b.len() { b[off] } else { 0 } }

/// Write a 32-bit field at `off`, ignoring a write past the buffer. # C: O(1)
pub fn w32(b: &mut [u8], off: usize, v: u32) {
    if off + 4 > b.len() { return; }
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Signed writing of the same word. # C: O(1)
pub fn w32i(b: &mut [u8], off: usize, v: i32) { w32(b, off, v as u32) }

/// Write a 64-bit field at `off`. # C: O(1)
pub fn w64(b: &mut [u8], off: usize, v: u64) {
    if off + 8 > b.len() { return; }
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Signed writing of the same doubleword. # C: O(1)
pub fn w64i(b: &mut [u8], off: usize, v: i64) { w64(b, off, v as u64) }

/// Write a single byte field. # C: O(1)
pub fn w8(b: &mut [u8], off: usize, v: u8) { if off < b.len() { b[off] = v; } }

/// Write a NUL-padded fixed-width name field, truncating a name that does not
/// fit and always leaving a terminating NUL. # C: O(cap)
pub fn wstr(b: &mut [u8], off: usize, cap: usize, s: &str) {
    if off + cap > b.len() || cap == 0 { return; }
    let bytes = s.as_bytes();
    let keep = core::cmp::min(bytes.len(), cap - 1);
    b[off..off + keep].copy_from_slice(&bytes[..keep]);
    for byte in b[off + keep..off + cap].iter_mut() { *byte = 0; }
}

/// Zero a reserved span. Every command the reference declares as zeroing its
/// reserved fields does so through this, so "which fields are cleared" is one
/// call site per structure rather than a scatter of loops. # C: O(len)
pub fn zero(b: &mut [u8], off: usize, len: usize) {
    if off + len > b.len() { return; }
    for byte in b[off..off + len].iter_mut() { *byte = 0; }
}
