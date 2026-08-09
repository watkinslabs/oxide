// Zero-copy receive ABI: the records `IORING_REGISTER_ZCRX_IFQ`,
// `IORING_REGISTER_ZCRX_CTRL` and `IORING_OP_RECV_ZC` exchange, and the
// admission that decides which of them is legal.
//
// Everything here is decision and layout only — no ring, no netdev, no page
// pool — so the whole ladder is exercised by hosted tests. The slot files copy
// the bytes and call in; they decide nothing (docs/53).
//
// Module manifest:
//   admit — the registration, control and receive admission ladders
//   refs  — the two per-buffer counts and the one order they may be spent in
//   tests — the ladder's order, which is what decides WHICH errno a caller
//           gets when several rungs would fail

#[path = "zcrx/admit.rs"] mod admit;
#[path = "zcrx/refs.rs"]  mod refs;
pub use admit::*;
pub use refs::{refill, Refill, UserRefs};

/// `sizeof(struct io_uring_zcrx_ifq_reg)`.
pub const IFQ_REG_BYTES: u64 = 96;
/// `sizeof(struct io_uring_zcrx_area_reg)`.
pub const AREA_REG_BYTES: u64 = 48;
/// `sizeof(struct zcrx_notification_desc)`.
pub const NOTIF_DESC_BYTES: u64 = 96;
/// `sizeof(struct zcrx_ctrl)`.
pub const CTRL_BYTES: u64 = 72;
/// `sizeof(struct io_uring_zcrx_rqe)`.
pub const RQE_BYTES: u64 = 16;
/// `sizeof(struct io_uring_zcrx_cqe)` — the `big_cqe` half of a receive
/// completion.
pub const ZCRX_CQE_BYTES: u64 = 16;
/// `sizeof(struct zcrx_notif_stats)`.
pub const NOTIF_STATS_BYTES: u64 = 16;

/// Bit from which an area id is encoded into a buffer offset.
pub const IORING_ZCRX_AREA_SHIFT: u32 = 48;
/// Mask of the area-id half of a buffer offset.
pub const IORING_ZCRX_AREA_MASK: u64 = !((1u64 << IORING_ZCRX_AREA_SHIFT) - 1);

/// Largest refill queue.
pub const IO_RQ_MAX_ENTRIES: u32 = 32768;

/// `enum zcrx_reg_flags`.
pub const ZCRX_REG_IMPORT: u32 = 1;
/// Register without a device: every byte is copied into the area, and the
/// refill queue is drained on demand rather than by a device.
pub const ZCRX_REG_NODEV:  u32 = 2;
/// Registration flags this kernel accepts.
pub const ZCRX_SUPPORTED_REG_FLAGS: u32 = ZCRX_REG_IMPORT | ZCRX_REG_NODEV;

/// `enum io_uring_zcrx_area_flags`.
pub const IORING_ZCRX_AREA_DMABUF: u32 = 1;
/// Area flags this kernel accepts. `DMABUF` is not among them: there is no
/// buffer-sharing framework to import from, and the reference's own
/// non-dmabuf path is the one a plain memory area takes.
pub const IO_ZCRX_AREA_SUPPORTED_FLAGS: u32 = IORING_ZCRX_AREA_DMABUF;

/// `enum zcrx_features`.
pub const ZCRX_FEATURE_RX_PAGE_SIZE: u32 = 1 << 0;
pub const ZCRX_FEATURE_NOTIFICATION: u32 = 1 << 1;
pub const ZCRX_FEATURES: u32 = ZCRX_FEATURE_RX_PAGE_SIZE | ZCRX_FEATURE_NOTIFICATION;

/// `enum zcrx_notification_type`.
pub const ZCRX_NOTIF_NO_BUFFERS: u32 = 0;
pub const ZCRX_NOTIF_COPY: u32 = 1;
pub const ZCRX_NOTIF_TYPE_LAST: u32 = 2;
/// Notification types a caller may ask for.
pub const ZCRX_NOTIF_TYPE_MASK: u32 = (1 << ZCRX_NOTIF_NO_BUFFERS) | (1 << ZCRX_NOTIF_COPY);
/// `enum zcrx_notification_desc_flags`.
pub const ZCRX_NOTIF_DESC_FLAG_STATS: u32 = 1 << 0;

/// `enum zcrx_ctrl_op`.
pub const ZCRX_CTRL_FLUSH_RQ: u32 = 0;
pub const ZCRX_CTRL_EXPORT: u32 = 1;
pub const ZCRX_CTRL_ARM_NOTIFICATION: u32 = 2;
pub const ZCRX_CTRL_LAST: u32 = 3;

/// `mmap(2)` offset the refill-queue region of zcrx instance `id` is published
/// at.
pub const IORING_MAP_OFF_ZCRX_REGION: u64 = 0x3000_0000;
/// Bits an instance id is shifted by inside that offset.
pub const IORING_OFF_ZCRX_SHIFT: u32 = 16;

/// Largest number of zcrx instances one ring may register. The bound is the
/// mmap offset, not the reference's id space: an id is shifted by
/// [`IORING_OFF_ZCRX_SHIFT`] into [`IORING_MAP_OFF_ZCRX_REGION`], and the
/// region selector occupies bits 27 and up, leaving eleven bits for the id.
/// An id that overflowed into the selector would publish a refill queue at an
/// offset that selects a different region entirely.
pub const ZCRX_MAX_IFQS: u32 = 1 << 11;

/// The zcrx instance an `mmap(2)` offset names, given that the offset already
/// selects the zcrx region. # C: O(1)
pub fn zcrx_mmap_id(offset: u64) -> u32 {
    ((offset - IORING_MAP_OFF_ZCRX_REGION) >> IORING_OFF_ZCRX_SHIFT) as u32
}

/// The `mmap(2)` offset instance `id`'s refill queue is published at.
/// # C: O(1)
pub fn zcrx_mmap_offset(id: u32) -> u64 {
    IORING_MAP_OFF_ZCRX_REGION + ((id as u64) << IORING_OFF_ZCRX_SHIFT)
}

/// Byte offsets inside the refill-queue region — Linux
/// `io_fill_zcrx_offsets`. `head` and `tail` are the two words of the region's
/// `struct io_uring` header; the entries start on their own cacheline.
pub const ZCRX_RQ_HEAD_OFF: u32 = 0;
pub const ZCRX_RQ_TAIL_OFF: u32 = 4;
/// `ALIGN(sizeof(struct io_uring), L1_CACHE_BYTES)`.
pub const ZCRX_RQ_RQES_OFF: u32 = 64;

/// `struct io_uring_zcrx_offsets`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ZcrxOffsets {
    pub head: u32,
    pub tail: u32,
    pub rqes: u32,
    pub resv2: u32,
    pub resv: [u64; 2],
}

impl ZcrxOffsets {
    /// The offsets every zcrx region has — the caller states none of them.
    /// # C: O(1)
    pub fn fill() -> Self {
        Self { head: ZCRX_RQ_HEAD_OFF, tail: ZCRX_RQ_TAIL_OFF, rqes: ZCRX_RQ_RQES_OFF,
               resv2: 0, resv: [0; 2] }
    }
}

/// `struct io_uring_zcrx_ifq_reg`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct IfqReg {
    pub if_idx: u32,
    pub if_rxq: u32,
    pub rq_entries: u32,
    pub flags: u32,
    pub area_ptr: u64,
    pub region_ptr: u64,
    pub offsets: ZcrxOffsets,
    pub zcrx_id: u32,
    pub rx_buf_len: u32,
    pub notif_desc: u64,
    pub resv: [u64; 2],
}

/// `struct io_uring_zcrx_area_reg`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AreaReg {
    pub addr: u64,
    pub len: u64,
    pub rq_area_token: u64,
    pub flags: u32,
    pub dmabuf_fd: u32,
    pub resv2: [u64; 2],
}

/// `struct zcrx_notification_desc`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NotifDesc {
    pub user_data: u64,
    pub type_mask: u32,
    pub flags: u32,
    pub stats_offset: u64,
    pub resv2: [u64; 9],
}

/// `struct zcrx_ctrl` — the fixed head, plus the 48-byte union body every
/// operation reads its own shape out of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ctrl {
    pub zcrx_id: u32,
    pub op: u32,
    pub resv: [u64; 2],
    pub body: [u8; 48],
}

impl Default for Ctrl {
    fn default() -> Self { Self { zcrx_id: 0, op: 0, resv: [0; 2], body: [0; 48] } }
}

/// Read a little-endian `u32` at `o`. # C: O(1)
fn g32(b: &[u8], o: usize) -> u32 { u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) }
/// Read a little-endian `u64` at `o`. # C: O(1)
fn g64(b: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes([b[o], b[o+1], b[o+2], b[o+3], b[o+4], b[o+5], b[o+6], b[o+7]])
}
/// Write a `u32` at `o`. # C: O(1)
fn p32(b: &mut [u8], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_ne_bytes()); }
/// Write a `u64` at `o`. # C: O(1)
fn p64(b: &mut [u8], o: usize, v: u64) { b[o..o + 8].copy_from_slice(&v.to_ne_bytes()); }

impl IfqReg {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; IFQ_REG_BYTES as usize]) -> Self {
        Self {
            if_idx: g32(b, 0), if_rxq: g32(b, 4), rq_entries: g32(b, 8), flags: g32(b, 12),
            area_ptr: g64(b, 16), region_ptr: g64(b, 24),
            offsets: ZcrxOffsets {
                head: g32(b, 32), tail: g32(b, 36), rqes: g32(b, 40), resv2: g32(b, 44),
                resv: [g64(b, 48), g64(b, 56)],
            },
            zcrx_id: g32(b, 64), rx_buf_len: g32(b, 68), notif_desc: g64(b, 72),
            resv: [g64(b, 80), g64(b, 88)],
        }
    }

    /// # C: O(1)
    pub fn to_bytes(&self) -> [u8; IFQ_REG_BYTES as usize] {
        let mut b = [0u8; IFQ_REG_BYTES as usize];
        p32(&mut b, 0, self.if_idx); p32(&mut b, 4, self.if_rxq);
        p32(&mut b, 8, self.rq_entries); p32(&mut b, 12, self.flags);
        p64(&mut b, 16, self.area_ptr); p64(&mut b, 24, self.region_ptr);
        p32(&mut b, 32, self.offsets.head); p32(&mut b, 36, self.offsets.tail);
        p32(&mut b, 40, self.offsets.rqes); p32(&mut b, 44, self.offsets.resv2);
        p64(&mut b, 48, self.offsets.resv[0]); p64(&mut b, 56, self.offsets.resv[1]);
        p32(&mut b, 64, self.zcrx_id); p32(&mut b, 68, self.rx_buf_len);
        p64(&mut b, 72, self.notif_desc);
        p64(&mut b, 80, self.resv[0]); p64(&mut b, 88, self.resv[1]);
        b
    }
}

impl AreaReg {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; AREA_REG_BYTES as usize]) -> Self {
        Self {
            addr: g64(b, 0), len: g64(b, 8), rq_area_token: g64(b, 16),
            flags: g32(b, 24), dmabuf_fd: g32(b, 28), resv2: [g64(b, 32), g64(b, 40)],
        }
    }

    /// # C: O(1)
    pub fn to_bytes(&self) -> [u8; AREA_REG_BYTES as usize] {
        let mut b = [0u8; AREA_REG_BYTES as usize];
        p64(&mut b, 0, self.addr); p64(&mut b, 8, self.len);
        p64(&mut b, 16, self.rq_area_token);
        p32(&mut b, 24, self.flags); p32(&mut b, 28, self.dmabuf_fd);
        p64(&mut b, 32, self.resv2[0]); p64(&mut b, 40, self.resv2[1]);
        b
    }
}

impl NotifDesc {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; NOTIF_DESC_BYTES as usize]) -> Self {
        let mut resv2 = [0u64; 9];
        for (i, slot) in resv2.iter_mut().enumerate() { *slot = g64(b, 24 + i * 8); }
        Self { user_data: g64(b, 0), type_mask: g32(b, 8), flags: g32(b, 12),
               stats_offset: g64(b, 16), resv2 }
    }
}

impl Ctrl {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; CTRL_BYTES as usize]) -> Self {
        let mut body = [0u8; 48];
        body.copy_from_slice(&b[24..72]);
        Self { zcrx_id: g32(b, 0), op: g32(b, 4), resv: [g64(b, 8), g64(b, 16)], body }
    }

    /// The union body read as `struct zcrx_ctrl_arm_notif` — a type and eleven
    /// reserved words. # C: O(1)
    pub fn arm_notif(&self) -> (u32, bool) {
        let ty = g32(&self.body, 0);
        (ty, self.body[4..48].iter().all(|&x| x == 0))
    }

    /// The union body read as `struct zcrx_ctrl_flush_rq` — six reserved
    /// words; true when they are all zero. # C: O(1)
    pub fn flush_resv_clear(&self) -> bool { self.body.iter().all(|&x| x == 0) }
}

/// One refill-queue entry — `struct io_uring_zcrx_rqe`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Rqe {
    pub off: u64,
    pub len: u32,
    pub pad: u32,
}

impl Rqe {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; RQE_BYTES as usize]) -> Self {
        Self { off: g64(b, 0), len: g32(b, 8), pad: g32(b, 12) }
    }
    /// # C: O(1)
    pub fn to_bytes(&self) -> [u8; RQE_BYTES as usize] {
        let mut b = [0u8; RQE_BYTES as usize];
        p64(&mut b, 0, self.off); p32(&mut b, 8, self.len); p32(&mut b, 12, self.pad);
        b
    }
}

/// The `big_cqe` half a receive completion carries: where in the area the
/// bytes landed. # C: O(1)
pub fn zcrx_cqe(area_id: u16, byte_off: u64) -> [u64; 2] {
    [byte_off + ((area_id as u64) << IORING_ZCRX_AREA_SHIFT), 0]
}

#[cfg(test)]
#[path = "zcrx/tests.rs"]
mod tests;
