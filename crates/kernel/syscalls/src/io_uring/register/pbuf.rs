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
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::pin::PinnedRange;
use crate::io_uring::rsrc::{BufGroup, BufRing, ProvidedBuf};
use crate::io_uring_abi::acct::Ledgers;
use crate::io_uring_abi::bundle::{BufEntry, IncCommit};
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
    // `min_left`: the smallest remainder worth handing back on an
    // incrementally-consumed group. Stored as one less, so that a group
    // registered without one keeps every remainder down to a single byte.
    let min_left = u32::from_ne_bytes([b[16], b[17], b[18], b[19]]);
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
    // A provided-buffer ring is the RING's memory, whoever supplied the pages:
    // the user account alone, like every other region.
    let pinned = match PinnedRange::pin(ring_addr, bytes, inode.acct, Ledgers::User) {
        Ok(p) => p, Err(e) => return err(e),
    };

    let mut g = inode.reg.lock();
    if g.bufs_groups.iter().any(|x| x.gid == bgid) { return err(Errno::Eexist); }
    if g.bufs_groups.try_reserve(1).is_err() { return err(Errno::Enomem); }
    g.bufs_groups.push(BufGroup {
        gid: bgid,
        bufs: Default::default(),
        ring: Some(BufRing {
            mem: Arc::new(pinned), entries, head: 0,
            incremental: flags & IOU_PBUF_RING_INC != 0,
            min_left_sub_one: min_left.saturating_sub(1),
        }),
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

/// Byte offset of an entry's length field inside `struct io_uring_buf`.
const BUF_LEN_OFF: u64 = 8;

impl BufRing {
    /// The tail the caller has published. # C: O(1)
    pub fn tail(&self) -> Result<u16, Errno> {
        let mut t = [0u8; 2];
        self.mem.read_at(RING_TAIL_OFF, &mut t)?;
        Ok(u16::from_ne_bytes(t))
    }

    /// Byte offset of the entry `i` slots past the head. # C: O(1)
    fn slot_off(&self, i: u32) -> u64 {
        let mask = (self.entries - 1) as u16;
        ((self.head as u16).wrapping_add(i as u16) & mask) as u64 * BUF_BYTES
    }

    /// Read the entry `i` slots past the head, without consuming it. # C: O(1)
    fn entry(&self, i: u32) -> Result<BufEntry, Errno> {
        let mut rec = [0u8; BUF_BYTES as usize];
        self.mem.read_at(self.slot_off(i), &mut rec)?;
        Ok(BufEntry {
            addr: u64::from_ne_bytes([rec[0], rec[1], rec[2], rec[3], rec[4], rec[5], rec[6], rec[7]]),
            len: u32::from_ne_bytes([rec[8], rec[9], rec[10], rec[11]]),
            bid: u16::from_ne_bytes([rec[12], rec[13]]),
        })
    }

    /// Take the entry at the ring's head. # C: O(1)
    pub fn next(&mut self) -> Result<ProvidedBuf, Errno> {
        if self.available() == 0 { return Err(Errno::Enobufs); }
        let e = self.entry(0)?;
        self.head = self.head.wrapping_add(1);
        Ok(ProvidedBuf { addr: e.addr, len: e.len, bid: e.bid })
    }

    /// Read the published run starting at the head, up to `n` entries and
    /// never past what the caller has actually published. The head does not
    /// move: what the transfer consumed is settled afterwards, by how much of
    /// the run it reached. # C: O(n)
    pub fn peek(&self, n: usize, out: &mut Vec<BufEntry>) -> Result<(), Errno> {
        let n = core::cmp::min(n, self.available() as usize);
        out.try_reserve(n).map_err(|_| Errno::Enomem)?;
        for i in 0..n { out.push(self.entry(i as u32)?); }
        Ok(())
    }

    /// Advance the head past `n` entries the transfer used up. # C: O(1)
    pub fn commit_whole(&mut self, n: usize) {
        self.head = self.head.wrapping_add(n as u32);
    }

    /// Apply an incremental commit: retired entries lose their published
    /// length and the head moves past them, and the entry the transfer stopped
    /// inside is rewritten to its remainder and KEPT — the same buffer id
    /// serves the next operation. # C: O(entries retired)
    pub fn commit_inc(&mut self, c: IncCommit) -> Result<(), Errno> {
        for i in 0..c.whole as u32 {
            self.mem.write_at(self.slot_off(i) + BUF_LEN_OFF, &0u32.to_ne_bytes())?;
        }
        if let Some((addr, len)) = c.partial {
            let at = self.slot_off(c.whole as u32);
            self.mem.write_at(at, &addr.to_ne_bytes())?;
            self.mem.write_at(at + BUF_LEN_OFF, &len.to_ne_bytes())?;
        }
        self.head = self.head.wrapping_add(c.whole as u32);
        Ok(())
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
