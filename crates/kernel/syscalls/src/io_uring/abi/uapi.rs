// Linux io_uring UAPI numbers + `struct io_uring_params` wire form:
// IORING_SETUP_*, IORING_FEAT_*, IORING_OFF_*, `struct io_uring_params`,
// `struct io_{sq,cq}ring_offsets`, and the IORING_SETUP_FLAGS /
// IORING_FEAT_FLAGS / IORING_MAX_ENTRIES masks.
// UAPI is not policy (CLAUDE.md): admission rules live in `layout`/`register_op`.

/// `IORING_SETUP_IOPOLL` — polled completion (`io_context is polled`).
pub const IORING_SETUP_IOPOLL:            u32 = 1 << 0;
/// `IORING_SETUP_SQPOLL` — kernel SQ poll thread.
pub const IORING_SETUP_SQPOLL:            u32 = 1 << 1;
/// `IORING_SETUP_SQ_AFF` — `sq_thread_cpu` is valid.
pub const IORING_SETUP_SQ_AFF:            u32 = 1 << 2;
/// `IORING_SETUP_CQSIZE` — caller sizes the CQ ring via `p->cq_entries`.
pub const IORING_SETUP_CQSIZE:            u32 = 1 << 3;
/// `IORING_SETUP_CLAMP` — clamp oversized SQ/CQ requests instead of `EINVAL`.
pub const IORING_SETUP_CLAMP:             u32 = 1 << 4;
/// `IORING_SETUP_ATTACH_WQ` — share an existing ring's io-wq (`p->wq_fd`).
pub const IORING_SETUP_ATTACH_WQ:         u32 = 1 << 5;
/// `IORING_SETUP_R_DISABLED` — ring starts disabled until `ENABLE_RINGS`.
pub const IORING_SETUP_R_DISABLED:        u32 = 1 << 6;
/// `IORING_SETUP_SUBMIT_ALL` — keep submitting after a failed SQE.
pub const IORING_SETUP_SUBMIT_ALL:        u32 = 1 << 7;
/// `IORING_SETUP_COOP_TASKRUN` — no IPI needed to signal task work.
pub const IORING_SETUP_COOP_TASKRUN:      u32 = 1 << 8;
/// `IORING_SETUP_TASKRUN_FLAG` — surface pending task work in `sq_flags`.
pub const IORING_SETUP_TASKRUN_FLAG:      u32 = 1 << 9;
/// `IORING_SETUP_SQE128` — 128-byte SQEs.
pub const IORING_SETUP_SQE128:            u32 = 1 << 10;
/// `IORING_SETUP_CQE32` — 32-byte CQEs.
pub const IORING_SETUP_CQE32:             u32 = 1 << 11;
/// `IORING_SETUP_SINGLE_ISSUER` — only one task may submit.
pub const IORING_SETUP_SINGLE_ISSUER:     u32 = 1 << 12;
/// `IORING_SETUP_DEFER_TASKRUN` — run task work only from the submitter.
pub const IORING_SETUP_DEFER_TASKRUN:     u32 = 1 << 13;
/// `IORING_SETUP_NO_MMAP` — caller supplies the ring memory.
pub const IORING_SETUP_NO_MMAP:           u32 = 1 << 14;
/// `IORING_SETUP_REGISTERED_FD_ONLY` — install the ring only as a registered fd.
pub const IORING_SETUP_REGISTERED_FD_ONLY:u32 = 1 << 15;
/// `IORING_SETUP_NO_SQARRAY` — SQ head/tail index the SQE array directly.
pub const IORING_SETUP_NO_SQARRAY:        u32 = 1 << 16;
/// `IORING_SETUP_HYBRID_IOPOLL` — hybrid polling (requires IOPOLL).
pub const IORING_SETUP_HYBRID_IOPOLL:     u32 = 1 << 17;
/// `IORING_SETUP_CQE_MIXED` — 16- and 32-byte CQEs in one ring.
pub const IORING_SETUP_CQE_MIXED:         u32 = 1 << 18;
/// `IORING_SETUP_SQE_MIXED` — 64- and 128-byte SQEs in one ring.
pub const IORING_SETUP_SQE_MIXED:         u32 = 1 << 19;
/// `IORING_SETUP_SQ_REWIND` — caller may rewind the SQ tail.
pub const IORING_SETUP_SQ_REWIND:         u32 = 1 << 20;

/// `IORING_SETUP_FLAGS` — every setup bit Linux defines. A bit outside this
/// mask is `EINVAL` (`io_uring_sanitise_params`).
pub const IORING_SETUP_FLAGS: u32 =
    IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF
    | IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | IORING_SETUP_ATTACH_WQ
    | IORING_SETUP_R_DISABLED | IORING_SETUP_SUBMIT_ALL
    | IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG
    | IORING_SETUP_SQE128 | IORING_SETUP_CQE32 | IORING_SETUP_SINGLE_ISSUER
    | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_NO_MMAP
    | IORING_SETUP_REGISTERED_FD_ONLY | IORING_SETUP_NO_SQARRAY
    | IORING_SETUP_HYBRID_IOPOLL | IORING_SETUP_CQE_MIXED
    | IORING_SETUP_SQE_MIXED | IORING_SETUP_SQ_REWIND;

/// `IORING_FEAT_SINGLE_MMAP` — the CQ ring lives inside the SQ-ring mapping.
pub const IORING_FEAT_SINGLE_MMAP:     u32 = 1 << 0;
/// `IORING_FEAT_NODROP` — completions are never dropped on CQ overflow.
pub const IORING_FEAT_NODROP:          u32 = 1 << 1;
/// `IORING_FEAT_SUBMIT_STABLE` — SQE data is consumed before submit returns.
pub const IORING_FEAT_SUBMIT_STABLE:   u32 = 1 << 2;
/// `IORING_FEAT_RW_CUR_POS` — `off == -1` means "use the file position".
pub const IORING_FEAT_RW_CUR_POS:      u32 = 1 << 3;
/// `IORING_FEAT_CUR_PERSONALITY` — ops run under the submitter's creds.
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
/// `IORING_FEAT_FAST_POLL` — internal poll-armed retry for pollable files.
pub const IORING_FEAT_FAST_POLL:       u32 = 1 << 5;
/// `IORING_FEAT_POLL_32BITS` — full 32-bit poll masks.
pub const IORING_FEAT_POLL_32BITS:     u32 = 1 << 6;
/// `IORING_FEAT_SQPOLL_NONFIXED` — SQPOLL works with non-registered files.
pub const IORING_FEAT_SQPOLL_NONFIXED:  u32 = 1 << 7;
/// `IORING_FEAT_EXT_ARG` — `io_uring_enter` accepts `io_uring_getevents_arg`.
pub const IORING_FEAT_EXT_ARG:         u32 = 1 << 8;
/// `IORING_FEAT_NATIVE_WORKERS` — io-wq workers are real kernel threads.
pub const IORING_FEAT_NATIVE_WORKERS:  u32 = 1 << 9;
/// `IORING_FEAT_RSRC_TAGS` — tagged resource registration.
pub const IORING_FEAT_RSRC_TAGS:       u32 = 1 << 10;
/// `IORING_FEAT_CQE_SKIP` — `IOSQE_CQE_SKIP_SUCCESS`.
pub const IORING_FEAT_CQE_SKIP:        u32 = 1 << 11;
/// `IORING_FEAT_LINKED_FILE` — linked SQEs resolve their file at prep time.
pub const IORING_FEAT_LINKED_FILE:     u32 = 1 << 12;
/// `IORING_FEAT_REG_REG_RING` — registered rings may register rings.
pub const IORING_FEAT_REG_REG_RING:    u32 = 1 << 13;

/// mmap magic offsets (`IORING_OFF_*`).
pub const IORING_OFF_SQ_RING:   u64 = 0;
/// `IORING_OFF_CQ_RING`.
pub const IORING_OFF_CQ_RING:   u64 = 0x800_0000;
/// `IORING_OFF_SQES`.
pub const IORING_OFF_SQES:      u64 = 0x1000_0000;
/// `IORING_OFF_PBUF_RING`.
pub const IORING_OFF_PBUF_RING: u64 = 0x8000_0000;
/// `IORING_OFF_MMAP_MASK` — the region selector bits of an mmap offset.
pub const IORING_OFF_MMAP_MASK: u64 = 0xf800_0000;

/// `sq_ring->flags` bit `IORING_SQ_NEED_WAKEUP`.
pub const IORING_SQ_NEED_WAKEUP:  u32 = 1 << 0;
/// `sq_ring->flags` bit `IORING_SQ_CQ_OVERFLOW`.
pub const IORING_SQ_CQ_OVERFLOW:  u32 = 1 << 1;
/// `sq_ring->flags` bit `IORING_SQ_TASKRUN`.
pub const IORING_SQ_TASKRUN:      u32 = 1 << 2;

/// `sizeof(struct io_uring_sqe)`.
pub const SQE_SIZE: usize = 64;
/// `sizeof(struct io_uring_cqe)`.
pub const CQE_SIZE: usize = 16;
/// `sizeof(struct io_uring_params)`.
pub const PARAMS_SIZE: usize = 120;
/// `offsetof(struct io_uring_params, sq_off)`.
pub const PARAMS_SQ_OFF: usize = 40;
/// `offsetof(struct io_uring_params, cq_off)`.
pub const PARAMS_CQ_OFF: usize = 80;

/// `struct io_sqring_offsets`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct SqringOffsets {
    pub head: u32, pub tail: u32, pub ring_mask: u32, pub ring_entries: u32,
    pub flags: u32, pub dropped: u32, pub array: u32, pub resv1: u32,
    pub user_addr: u64,
}

/// `struct io_cqring_offsets`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct CqringOffsets {
    pub head: u32, pub tail: u32, pub ring_mask: u32, pub ring_entries: u32,
    pub overflow: u32, pub cqes: u32, pub flags: u32, pub resv1: u32,
    pub user_addr: u64,
}

/// `struct io_uring_params` — in AND out parameter of `io_uring_setup(2)`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Params {
    pub sq_entries: u32, pub cq_entries: u32, pub flags: u32,
    pub sq_thread_cpu: u32, pub sq_thread_idle: u32, pub features: u32,
    pub wq_fd: u32, pub resv: [u32; 3],
    pub sq_off: SqringOffsets, pub cq_off: CqringOffsets,
}

/// Read a little-endian `u32` at `off`. # C: O(1)
fn g32(b: &[u8; PARAMS_SIZE], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Read a little-endian `u64` at `off`. # C: O(1)
fn g64(b: &[u8; PARAMS_SIZE], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Write a little-endian `u32` at `off`. # C: O(1)
fn p32(b: &mut [u8; PARAMS_SIZE], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Write a little-endian `u64` at `off`. # C: O(1)
fn p64(b: &mut [u8; PARAMS_SIZE], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

impl Params {
    /// Decode the 120-byte user image. # C: O(1)
    pub fn from_bytes(b: &[u8; PARAMS_SIZE]) -> Self {
        let s = PARAMS_SQ_OFF; let c = PARAMS_CQ_OFF;
        Self {
            sq_entries: g32(b, 0), cq_entries: g32(b, 4), flags: g32(b, 8),
            sq_thread_cpu: g32(b, 12), sq_thread_idle: g32(b, 16),
            features: g32(b, 20), wq_fd: g32(b, 24),
            resv: [g32(b, 28), g32(b, 32), g32(b, 36)],
            sq_off: SqringOffsets {
                head: g32(b, s), tail: g32(b, s + 4), ring_mask: g32(b, s + 8),
                ring_entries: g32(b, s + 12), flags: g32(b, s + 16),
                dropped: g32(b, s + 20), array: g32(b, s + 24),
                resv1: g32(b, s + 28), user_addr: g64(b, s + 32),
            },
            cq_off: CqringOffsets {
                head: g32(b, c), tail: g32(b, c + 4), ring_mask: g32(b, c + 8),
                ring_entries: g32(b, c + 12), overflow: g32(b, c + 16),
                cqes: g32(b, c + 20), flags: g32(b, c + 24),
                resv1: g32(b, c + 28), user_addr: g64(b, c + 32),
            },
        }
    }

    /// Encode the 120-byte user image. # C: O(1)
    pub fn to_bytes(&self) -> [u8; PARAMS_SIZE] {
        let mut b = [0u8; PARAMS_SIZE];
        let s = PARAMS_SQ_OFF; let c = PARAMS_CQ_OFF;
        p32(&mut b, 0, self.sq_entries); p32(&mut b, 4, self.cq_entries);
        p32(&mut b, 8, self.flags); p32(&mut b, 12, self.sq_thread_cpu);
        p32(&mut b, 16, self.sq_thread_idle); p32(&mut b, 20, self.features);
        p32(&mut b, 24, self.wq_fd);
        p32(&mut b, 28, self.resv[0]); p32(&mut b, 32, self.resv[1]); p32(&mut b, 36, self.resv[2]);
        p32(&mut b, s, self.sq_off.head); p32(&mut b, s + 4, self.sq_off.tail);
        p32(&mut b, s + 8, self.sq_off.ring_mask); p32(&mut b, s + 12, self.sq_off.ring_entries);
        p32(&mut b, s + 16, self.sq_off.flags); p32(&mut b, s + 20, self.sq_off.dropped);
        p32(&mut b, s + 24, self.sq_off.array); p32(&mut b, s + 28, self.sq_off.resv1);
        p64(&mut b, s + 32, self.sq_off.user_addr);
        p32(&mut b, c, self.cq_off.head); p32(&mut b, c + 4, self.cq_off.tail);
        p32(&mut b, c + 8, self.cq_off.ring_mask); p32(&mut b, c + 12, self.cq_off.ring_entries);
        p32(&mut b, c + 16, self.cq_off.overflow); p32(&mut b, c + 20, self.cq_off.cqes);
        p32(&mut b, c + 24, self.cq_off.flags); p32(&mut b, c + 28, self.cq_off.resv1);
        p64(&mut b, c + 32, self.cq_off.user_addr);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire offsets that slot 425 used to hard-code as `params + 40 + N`
    /// and `params + 72 + N`. `cq_off` starts at 80, not 72: `io_sqring_offsets`
    /// is 8 `__u32` + one `__u64` = 40 bytes, so writing the CQ offsets at +72
    /// landed them inside `sq_off.array`/`sq_off.resv1`/`sq_off.user_addr`.
    #[test]
    fn params_wire_layout_matches_linux_uapi() {
        assert_eq!(PARAMS_SIZE, 120);
        assert_eq!(PARAMS_SQ_OFF, 40);
        assert_eq!(PARAMS_CQ_OFF, 80);
        let mut p = Params::default();
        p.cq_off.head = 0xC0FFEE01;
        let b = p.to_bytes();
        assert_eq!(g32(&b, 80), 0xC0FFEE01);
        assert_eq!(g32(&b, 72), 0, "cq_off.head must not land in sq_off.user_addr");
    }

    #[test]
    fn params_roundtrip_every_field() {
        let p = Params {
            sq_entries: 1, cq_entries: 2, flags: 3, sq_thread_cpu: 4,
            sq_thread_idle: 5, features: 6, wq_fd: 7, resv: [8, 9, 10],
            sq_off: SqringOffsets { head: 11, tail: 12, ring_mask: 13, ring_entries: 14,
                                    flags: 15, dropped: 16, array: 17, resv1: 18, user_addr: 19 },
            cq_off: CqringOffsets { head: 20, tail: 21, ring_mask: 22, ring_entries: 23,
                                    overflow: 24, cqes: 25, flags: 26, resv1: 27, user_addr: 28 },
        };
        assert_eq!(Params::from_bytes(&p.to_bytes()), p);
    }

    #[test]
    fn setup_flag_mask_covers_every_defined_bit_and_nothing_else() {
        // Linux io_uring UAPI IORING_SETUP_FLAGS: bits 0..=20.
        assert_eq!(IORING_SETUP_FLAGS, (1u32 << 21) - 1);
        assert_eq!(IORING_SETUP_SQ_REWIND, 1 << 20);
    }

    #[test]
    fn mmap_region_selectors_are_distinct_under_the_mask() {
        assert_eq!(IORING_OFF_SQ_RING & IORING_OFF_MMAP_MASK, 0);
        assert_ne!(IORING_OFF_CQ_RING & IORING_OFF_MMAP_MASK,
                   IORING_OFF_SQES & IORING_OFF_MMAP_MASK);
        assert_eq!(IORING_OFF_PBUF_RING & IORING_OFF_MMAP_MASK, IORING_OFF_PBUF_RING);
    }
}
