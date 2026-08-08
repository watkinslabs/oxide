// Provided-buffer rings.
//
// A buffer ring is memory the caller owns and the kernel reads: an array of
// `struct io_uring_buf` entries with a tail the caller advances as it publishes
// buffers, and a head the kernel advances as it consumes them. It replaces the
// per-buffer registration of the classic provided-buffer groups with a single
// shared array, which is why a receiving loop can refill it without a syscall.
//
// The ring memory is PINNED at registration, like a registered buffer: the
// kernel reads entries out of the pinned frames, so nothing the process later
// does to its mappings can retarget the array the kernel is reading.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::pin::PinnedRange;
use crate::io_uring::rsrc::{BufGroup, BufRing, ProvidedBuf};
use crate::io_uring_abi::register_op::BUF_REG_BYTES;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sizeof(struct io_uring_buf)` — {addr u64, len u32, bid u16, resv u16}.
pub const BUF_BYTES: u64 = 16;
/// Byte offset of the ring tail, which overlaps the first entry's tail half.
pub const RING_TAIL_OFF: u64 = 14;
/// `IOU_PBUF_RING_MMAP` — ask the kernel to provide the ring memory.
pub const IOU_PBUF_RING_MMAP: u16 = 1;
/// `IOU_PBUF_RING_INC` — buffers are consumed incrementally.
pub const IOU_PBUF_RING_INC: u16 = 2;

/// `IORING_REGISTER_PBUF_RING`. # C: O(ring bytes / PAGE)
pub fn register(inode: &IoUringInode, arg: u64) -> i64 {
    let mut b = [0u8; BUF_REG_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let ring_addr = u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let entries = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
    let bgid = u16::from_ne_bytes([b[12], b[13]]);
    let flags = u16::from_ne_bytes([b[14], b[15]]);
    if b[20..].iter().any(|&x| x != 0) { return err(Errno::Einval); }
    if entries == 0 || !entries.is_power_of_two() || entries > (1 << 15) { return err(Errno::Einval); }
    if flags & !(IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC) != 0 { return err(Errno::Einval); }
    // Kernel-provided ring memory would need a mapping region of its own; the
    // caller-provided form is the one this kernel serves, and asking for the
    // other must not look like it succeeded.
    if flags & IOU_PBUF_RING_MMAP != 0 { return err(Errno::Einval); }
    if ring_addr == 0 || ring_addr & (BUF_BYTES - 1) != 0 { return err(Errno::Einval); }

    let bytes = match (entries as u64).checked_mul(BUF_BYTES) {
        Some(v) => v, None => return err(Errno::Eoverflow),
    };
    let pinned = match PinnedRange::pin(ring_addr, bytes) { Ok(p) => p, Err(e) => return err(e) };

    let mut g = inode.reg.lock();
    if g.bufs_groups.iter().any(|x| x.gid == bgid) { return err(Errno::Eexist); }
    if g.bufs_groups.try_reserve(1).is_err() { return err(Errno::Enomem); }
    g.bufs_groups.push(BufGroup {
        gid: bgid,
        bufs: Default::default(),
        ring: Some(BufRing { mem: Arc::new(pinned), entries, head: 0, incremental: flags & IOU_PBUF_RING_INC != 0 }),
    });
    0
}

/// `IORING_UNREGISTER_PBUF_RING`. # C: O(N_groups)
pub fn unregister(inode: &IoUringInode, arg: u64) -> i64 {
    let mut b = [0u8; BUF_REG_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let bgid = u16::from_ne_bytes([b[12], b[13]]);
    let mut g = inode.reg.lock();
    let Some(i) = g.bufs_groups.iter().position(|x| x.gid == bgid && x.ring.is_some()) else {
        return err(Errno::Einval);
    };
    g.bufs_groups.remove(i);
    0
}

impl BufRing {
    /// The tail the caller has published. # C: O(1)
    pub fn tail(&self) -> Result<u16, Errno> {
        let mut t = [0u8; 2];
        let mut out = [0u8; 2];
        self.mem.for_each_chunk(RING_TAIL_OFF, 2, |chunk| {
            let n = core::cmp::min(chunk.len(), 2);
            out[..n].copy_from_slice(&chunk[..n]);
            Some(n)
        })?;
        t.copy_from_slice(&out);
        Ok(u16::from_ne_bytes(t))
    }

    /// Take the entry at the ring's head. # C: O(1)
    pub fn next(&mut self) -> Result<ProvidedBuf, Errno> {
        let tail = self.tail()?;
        let mask = (self.entries - 1) as u16;
        let head = self.head as u16;
        if head == tail { return Err(Errno::Enobufs); }
        let at = (head & mask) as u64 * BUF_BYTES;
        let mut rec = [0u8; BUF_BYTES as usize];
        let mut got = 0usize;
        self.mem.for_each_chunk(at, BUF_BYTES, |chunk| {
            let n = chunk.len();
            rec[got..got + n].copy_from_slice(chunk);
            got += n;
            Some(n)
        })?;
        self.head = self.head.wrapping_add(1);
        Ok(ProvidedBuf {
            addr: u64::from_ne_bytes([rec[0], rec[1], rec[2], rec[3], rec[4], rec[5], rec[6], rec[7]]),
            len: u32::from_ne_bytes([rec[8], rec[9], rec[10], rec[11]]),
            bid: u16::from_ne_bytes([rec[12], rec[13]]),
        })
    }

    /// Buffers the caller has published and the kernel has not taken.
    /// # C: O(1)
    pub fn available(&self) -> u32 {
        match self.tail() {
            Ok(t) => t.wrapping_sub(self.head as u16) as u32,
            Err(_) => 0,
        }
    }
}
