// `struct perf_event_attr` decode + validation — Linux `kernel/events/core.c`
// `perf_copy_attr()`. Pure over a byte slice: no user pointers, no task state,
// so the whole extensible-struct protocol and every `-EINVAL` in Linux's order
// is unit-testable hosted.

use syscall::errno::Errno;

use super::uapi::{attr_bit, attr_off, attr_size, branch, fmt, regs, sample};

/// Decoded `struct perf_event_attr`. Only the fields the open/read/ioctl paths
/// consult; the rest are validated in place and dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PerfAttr {
    pub ty:                u32,
    pub size:              u32,
    pub config:            u64,
    pub sample_period:     u64,
    pub sample_type:       u64,
    pub read_format:       u64,
    pub bits:              u64,
    pub branch_sample_type:u64,
    pub clockid:           i32,
}

/// `perf_copy_attr` failure. `E2big` additionally makes Linux write
/// `sizeof(struct perf_event_attr)` back into `uattr->size`; the caller owns
/// that copyout so this stays pure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrErr {
    /// `-E2BIG` + `put_user(sizeof(*attr), &uattr->size)`.
    TooBig,
    /// `-EINVAL` from one of the field checks.
    Invalid,
    /// `-EACCES` — a privileged branch-sample priv level without CAP_PERFMON.
    NeedsKernelAllow,
}

impl AttrErr {
    /// # C: O(1)
    pub fn errno(self) -> Errno {
        match self {
            AttrErr::TooBig           => Errno::E2big,
            AttrErr::Invalid          => Errno::Einval,
            AttrErr::NeedsKernelAllow => Errno::Eacces,
        }
    }
}

impl PerfAttr {
    /// # C: O(1)
    pub fn bit(&self, b: u32) -> bool { (self.bits >> b) & 1 == 1 }
    /// `is_sampling_event()` (`include/linux/perf_event.h`). # C: O(1)
    pub fn is_sampling(&self) -> bool { self.sample_period != 0 }
    /// `attr.freq` selects `sample_freq` over `sample_period` in the same union.
    /// # C: O(1)
    pub fn freq(&self) -> bool { self.bit(attr_bit::FREQ) }
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    if off + 4 > b.len() { return 0; }
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn rd_u64(b: &[u8], off: usize) -> u64 {
    if off + 8 > b.len() { return 0; }
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// `copy_struct_from_user`'s tail rule: bytes past the kernel's struct must be
/// zero, otherwise `-E2BIG`. # C: O(n)
fn tail_is_zero(b: &[u8]) -> bool {
    b.iter().skip(attr_size::CURRENT as usize).all(|&x| x == 0)
}

/// `perf_copy_attr(uattr, attr)` over the already-fetched bytes.
///
/// `raw` must be the `size` bytes the caller read from userspace, where `size`
/// is the value taken from `uattr->size` *after* the ABI-compat quirk
/// (`size == 0` means `PERF_ATTR_SIZE_VER0`). `perfmon` is `perfmon_capable()`
/// and `paranoid` the live `kernel.perf_event_paranoid`; both are only consulted
/// for the branch-stack privileged-priv-level gate, which Linux performs inside
/// `perf_copy_attr` (before the `exclude_kernel` gate in the syscall body).
/// # C: O(size)
pub fn parse_attr(raw: &[u8], size: u32, paranoid: i32, perfmon: bool)
    -> Result<PerfAttr, AttrErr>
{
    // ABI compatibility quirk, then the VER0..PAGE_SIZE window.
    let size = if size == 0 { attr_size::VER0 } else { size };
    if size < attr_size::VER0 || size > attr_size::CEILING { return Err(AttrErr::TooBig); }
    if raw.len() < size as usize { return Err(AttrErr::Invalid); }
    let raw = &raw[..size as usize];
    if !tail_is_zero(raw) { return Err(AttrErr::TooBig); }

    let mut a = PerfAttr {
        ty:                 rd_u32(raw, attr_off::TYPE),
        size,
        config:             rd_u64(raw, attr_off::CONFIG),
        sample_period:      rd_u64(raw, attr_off::SAMPLE_PERIOD),
        sample_type:        rd_u64(raw, attr_off::SAMPLE_TYPE),
        read_format:        rd_u64(raw, attr_off::READ_FORMAT),
        bits:               rd_u64(raw, attr_off::BITS),
        branch_sample_type: rd_u64(raw, attr_off::BRANCH_SAMPLE_TYPE),
        clockid:            rd_u32(raw, attr_off::CLOCKID) as i32,
    };

    // `__reserved_1` (bitfield tail), `__reserved_2` (u16), `__reserved_3`
    // (inside the aux_action union) must all be zero.
    if a.bits & attr_bit::RESERVED_1_MASK != 0 { return Err(AttrErr::Invalid); }
    if rd_u32(raw, attr_off::RESERVED_2) & 0xFFFF != 0 { return Err(AttrErr::Invalid); }
    if rd_u32(raw, attr_off::AUX_ACTION) & attr_bit::AUX_RESERVED_3_MASK != 0 {
        return Err(AttrErr::Invalid);
    }

    if a.sample_type & !(sample::MAX - 1) != 0 { return Err(AttrErr::Invalid); }
    if a.read_format & !(fmt::MAX - 1)    != 0 { return Err(AttrErr::Invalid); }

    if a.sample_type & sample::BRANCH_STACK != 0 {
        let mut mask = a.branch_sample_type;
        if mask & !(branch::MAX - 1) != 0            { return Err(AttrErr::Invalid); }
        if mask & !branch::PLM_ALL == 0              { return Err(AttrErr::Invalid); }
        if mask & branch::PLM_ALL == 0 {
            if !a.bit(attr_bit::EXCLUDE_KERNEL) { mask |= branch::KERNEL; }
            if !a.bit(attr_bit::EXCLUDE_USER)   { mask |= branch::USER; }
            if !a.bit(attr_bit::EXCLUDE_HV)     { mask |= branch::HV; }
            a.branch_sample_type = mask;
        }
        if mask & branch::PERM_PLM != 0 && !allow_kernel(paranoid, perfmon) {
            return Err(AttrErr::NeedsKernelAllow);
        }
    }

    if a.sample_type & sample::REGS_USER != 0
        && !reg_mask_ok(rd_u64(raw, attr_off::SAMPLE_REGS_USER)) {
        return Err(AttrErr::Invalid);
    }

    if a.sample_type & sample::STACK_USER != 0 {
        // Both oxide arches set `HAVE_PERF_USER_STACK_DUMP`, so Linux's
        // `-ENOSYS` arm is unreachable; the size rules still apply.
        let ss = rd_u32(raw, attr_off::SAMPLE_STACK_USER);
        if ss >= u16::MAX as u32   { return Err(AttrErr::Invalid); }
        if ss % 8 != 0             { return Err(AttrErr::Invalid); }
    }

    if a.sample_type & sample::REGS_INTR != 0
        && !reg_mask_ok(rd_u64(raw, attr_off::SAMPLE_REGS_INTR)) {
        return Err(AttrErr::Invalid);
    }

    // `#ifndef CONFIG_CGROUP_PERF` arm: oxide has no perf cgroup controller.
    if a.sample_type & sample::CGROUP != 0 { return Err(AttrErr::Invalid); }

    if a.sample_type & sample::WEIGHT != 0 && a.sample_type & sample::WEIGHT_STRUCT != 0 {
        return Err(AttrErr::Invalid);
    }
    if !a.bit(attr_bit::INHERIT) && a.bit(attr_bit::INHERIT_THREAD) {
        return Err(AttrErr::Invalid);
    }
    if a.bit(attr_bit::REMOVE_ON_EXEC) && a.bit(attr_bit::ENABLE_ON_EXEC) {
        return Err(AttrErr::Invalid);
    }
    if a.bit(attr_bit::SIGTRAP) && !a.bit(attr_bit::REMOVE_ON_EXEC) {
        return Err(AttrErr::Invalid);
    }
    Ok(a)
}

/// `perf_reg_validate(mask)` == 0. # C: O(1)
pub fn reg_mask_ok(mask: u64) -> bool { mask != 0 && mask & regs::REJECT == 0 }

/// `perf_allow_kernel()` (`kernel/events/core.c`) minus the LSM hook.
/// # C: O(1)
pub fn allow_kernel(paranoid: i32, perfmon: bool) -> bool { paranoid <= 1 || perfmon }

/// `perf_allow_cpu()` (`include/linux/perf_event.h`). # C: O(1)
pub fn allow_cpu(paranoid: i32, perfmon: bool) -> bool { paranoid <= 0 || perfmon }
