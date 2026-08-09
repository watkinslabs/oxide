// `IORING_REGISTER_MEM_REGION` — the two wire structs, the admission ladder,
// and the registered-wait-argument offset check.
//
// A memory region is one of two things, chosen by the descriptor's flags:
//
//   kernel-allocated — pages this kernel owns, published to userspace at the
//                      parameter mmap offset the descriptor is told on the way
//                      out. The caller maps them and writes wait records there.
//   user-provided    — pages the CALLER already owns, pinned for the region's
//                      whole life. Never mappable from the ring fd: they are
//                      already in the caller's address space, and the
//                      reference refuses the `mmap` outright.
//
// The second form is why a region is not a single contiguous run: a pinned
// user range is whatever physical pages happened to back it. The accessor is
// therefore page-walking (`io_uring::pin`), not pointer arithmetic on one base.
//
// Registering the region with `IORING_MEM_REGION_REG_WAIT_ARG` is what makes
// `IORING_ENTER_EXT_ARG_REG` work: from then on `argp` is a byte OFFSET into
// the region rather than a user pointer, and the wait record is read from
// there with no per-call `copy_from_user`.

use syscall::errno::Errno;

/// `sizeof(struct io_uring_mem_region_reg)` — {region_uptr u64, flags u64,
/// __resv[2] u64}.
pub const MEM_REGION_REG_BYTES: u64 = 32;
/// `sizeof(struct io_uring_region_desc)` — {user_addr u64, size u64, flags
/// u32, id u32, mmap_offset u64, __resv[4] u64}.
pub const REGION_DESC_BYTES: u64 = 64;

/// `IORING_MEM_REGION_TYPE_USER` — the region is backed by the caller's own
/// memory at `user_addr`, pinned by the kernel.
pub const IORING_MEM_REGION_TYPE_USER: u32 = 1;
/// `IORING_MEM_REGION_REG_WAIT_ARG` — expose the region as the registered
/// wait-argument area `IORING_ENTER_EXT_ARG_REG` reads from.
pub const IORING_MEM_REGION_REG_WAIT_ARG: u64 = 1;

/// `IORING_MAP_OFF_PARAM_REGION` — the `mmap(2)` offset a kernel-allocated
/// parameter region is published at. Distinct from every other region
/// selector under `IORING_OFF_MMAP_MASK`.
pub const IORING_MAP_OFF_PARAM_REGION: u64 = 0x2000_0000;

/// Largest region the descriptor may ask for, in pages. Past it the answer is
/// `E2BIG` — the reference's `INT_MAX` page ceiling.
pub const MAX_REGION_PAGES: u64 = i32::MAX as u64;

/// `struct io_uring_mem_region_reg`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MemRegionReg {
    pub region_uptr: u64,
    pub flags: u64,
    pub resv: [u64; 2],
}

/// `struct io_uring_region_desc`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RegionDesc {
    pub user_addr: u64,
    pub size: u64,
    pub flags: u32,
    pub id: u32,
    pub mmap_offset: u64,
    pub resv: [u64; 4],
}

/// # C: O(1)
fn g64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// # C: O(1)
fn g32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) }

impl MemRegionReg {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; MEM_REGION_REG_BYTES as usize]) -> Self {
        Self { region_uptr: g64(b, 0), flags: g64(b, 8), resv: [g64(b, 16), g64(b, 24)] }
    }
}

impl RegionDesc {
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; REGION_DESC_BYTES as usize]) -> Self {
        Self {
            user_addr: g64(b, 0), size: g64(b, 8),
            flags: g32(b, 16), id: g32(b, 20), mmap_offset: g64(b, 24),
            resv: [g64(b, 32), g64(b, 40), g64(b, 48), g64(b, 56)],
        }
    }

    /// The descriptor as it is written back to the caller — a kernel-allocated
    /// region reports the offset it may be mapped at. # C: O(1)
    pub fn to_bytes(&self) -> [u8; REGION_DESC_BYTES as usize] {
        let mut b = [0u8; REGION_DESC_BYTES as usize];
        b[0..8].copy_from_slice(&self.user_addr.to_le_bytes());
        b[8..16].copy_from_slice(&self.size.to_le_bytes());
        b[16..20].copy_from_slice(&self.flags.to_le_bytes());
        b[20..24].copy_from_slice(&self.id.to_le_bytes());
        b[24..32].copy_from_slice(&self.mmap_offset.to_le_bytes());
        for i in 0..4 { b[32 + i * 8..40 + i * 8].copy_from_slice(&self.resv[i].to_le_bytes()); }
        b
    }

    /// Whether the caller supplied the memory. # C: O(1)
    pub fn user_provided(&self) -> bool { self.flags & IORING_MEM_REGION_TYPE_USER != 0 }
}

/// The registration record's own rules, applied AFTER both structs have been
/// read: reserved words zero, no unknown flag, and the wait-argument form only
/// while the ring is still disabled.
///
/// The last rule is not cosmetic. A registration that installed the wait area
/// under a ring with live waiters would have to synchronise with tasks that
/// are already parked reading the old area; requiring the ring to be disabled
/// means there cannot be any. # C: O(1)
pub fn admit_mem_region_reg(reg: &MemRegionReg, ring_disabled: bool) -> Result<(), Errno> {
    if reg.resv != [0, 0] { return Err(Errno::Einval); }
    if reg.flags & !IORING_MEM_REGION_REG_WAIT_ARG != 0 { return Err(Errno::Einval); }
    if reg.flags & IORING_MEM_REGION_REG_WAIT_ARG != 0 && !ring_disabled {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// The descriptor's rules, in the reference's order. The order is the contract:
/// a descriptor that is BOTH mistyped and misaligned reports the type error,
/// and one whose size is absurd reports `E2BIG` before its alignment is
/// examined. # C: O(1)
pub fn admit_region_desc(rd: &RegionDesc, page: u64) -> Result<(), Errno> {
    if rd.resv != [0; 4] { return Err(Errno::Einval); }
    if rd.flags & !IORING_MEM_REGION_TYPE_USER != 0 { return Err(Errno::Einval); }
    // `user_addr` is set IFF the region is user-backed. Either half alone is a
    // descriptor that does not say what it means, and the reference calls that
    // EFAULT rather than EINVAL.
    if rd.user_provided() != (rd.user_addr != 0) { return Err(Errno::Efault); }
    if rd.size == 0 || rd.mmap_offset != 0 || rd.id != 0 { return Err(Errno::Einval); }
    if rd.size / page > MAX_REGION_PAGES { return Err(Errno::E2big); }
    if (rd.user_addr | rd.size) & (page - 1) != 0 { return Err(Errno::Einval); }
    rd.user_addr.checked_add(rd.size).ok_or(Errno::Eoverflow)?;
    Ok(())
}

/// `sizeof(struct io_uring_reg_wait)` — the record `IORING_ENTER_EXT_ARG_REG`
/// reads out of the registered wait area. Mirrors
/// `io_uring_abi::enter::REG_WAIT_BYTES`; asserted equal in the tests.
pub const REG_WAIT_BYTES: u64 = 64;

/// Alignment `argp` must satisfy when it is an offset into the wait area —
/// `sizeof(long)` on both target ABIs.
pub const REG_WAIT_ALIGN: u64 = 8;

/// Turn an `IORING_ENTER_EXT_ARG_REG` `argp` into a byte offset inside the
/// registered wait area, or `EFAULT`.
///
/// `wait_size` is zero for a ring that registered no wait area, which is what
/// makes "no region" and "offset past the region" the same answer without a
/// separate null test. # C: O(1)
pub fn ext_arg_reg_offset(argp: u64, wait_size: u64) -> Result<u64, Errno> {
    if argp % REG_WAIT_ALIGN != 0 { return Err(Errno::Efault); }
    let end = argp.checked_add(REG_WAIT_BYTES).ok_or(Errno::Efault)?;
    if end > wait_size { return Err(Errno::Efault); }
    Ok(argp)
}

#[cfg(test)]
#[path = "mem_region/tests.rs"]
mod tests;
