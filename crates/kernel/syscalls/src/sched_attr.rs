// `struct sched_attr` extensible-struct ABI for slots 314/315.
//
// Linux refs (v7.2.0-rc4):
//   include/uapi/linux/sched/types.h  — struct sched_attr, SCHED_ATTR_SIZE_VER{0,1}
//   include/uapi/linux/sched.h:139    — SCHED_FLAG_*
//   kernel/sched/sched.h:285          — SCHED_FLAG_SUGOV (kernel-internal)
//   kernel/sched/syscalls.c:872       — sched_copy_attr()
//   kernel/sched/syscalls.c:1060      — sys_sched_getattr()
//   include/linux/uaccess.h:393/490   — copy_struct_from_user/copy_struct_to_user
//   kernel/sched/syscalls.c:300-420   — uclamp_reset/__setscheduler_uclamp/uclamp_validate
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: the 314/315 slot files
// are kernel-gated, so any rule expressed inside them is invisible to
// `cargo test`. The size ladder, the trailing-byte protocol, the flag mask and
// the uclamp range rules all live here and the slots stay thin shims (docs/53).

use syscall::errno::Errno;

/// `SCHED_ATTR_SIZE_VER0` — sizeof the first published struct.
pub const SIZE_VER0: u32 = 48;
/// `SCHED_ATTR_SIZE_VER1` — VER0 + `sched_util_{min,max}`.
pub const SIZE_VER1: u32 = 56;
/// `sizeof(struct sched_attr)` as this kernel knows it.
pub const KSIZE: u32 = SIZE_VER1;
/// `sched_copy_attr` rejects any `attr->size` above `PAGE_SIZE`.
pub const MAX_SIZE: u32 = 4096;

// struct sched_attr field offsets (include/uapi/linux/sched/types.h).
const OFF_SIZE: usize = 0;
const OFF_POLICY: usize = 4;
const OFF_FLAGS: usize = 8;
const OFF_NICE: usize = 16;
const OFF_PRIORITY: usize = 20;
const OFF_RUNTIME: usize = 24;
const OFF_DEADLINE: usize = 32;
const OFF_PERIOD: usize = 40;
const OFF_UTIL_MIN: usize = 48;
const OFF_UTIL_MAX: usize = 52;

/// `SCHED_FLAG_RESET_ON_FORK`.
pub const FLAG_RESET_ON_FORK: u64 = 0x01;
/// `SCHED_FLAG_RECLAIM`.
pub const FLAG_RECLAIM: u64 = 0x02;
/// `SCHED_FLAG_DL_OVERRUN`.
pub const FLAG_DL_OVERRUN: u64 = 0x04;
/// `SCHED_FLAG_KEEP_POLICY`.
pub const FLAG_KEEP_POLICY: u64 = 0x08;
/// `SCHED_FLAG_KEEP_PARAMS`.
pub const FLAG_KEEP_PARAMS: u64 = 0x10;
/// `SCHED_FLAG_UTIL_CLAMP_MIN`.
pub const FLAG_UTIL_CLAMP_MIN: u64 = 0x20;
/// `SCHED_FLAG_UTIL_CLAMP_MAX`.
pub const FLAG_UTIL_CLAMP_MAX: u64 = 0x40;
/// `SCHED_FLAG_KEEP_ALL`.
pub const FLAG_KEEP_ALL: u64 = FLAG_KEEP_POLICY | FLAG_KEEP_PARAMS;
/// `SCHED_FLAG_UTIL_CLAMP`.
pub const FLAG_UTIL_CLAMP: u64 = FLAG_UTIL_CLAMP_MIN | FLAG_UTIL_CLAMP_MAX;
/// `SCHED_FLAG_ALL` — the whole user-settable set.
pub const FLAG_ALL: u64 =
    FLAG_RESET_ON_FORK | FLAG_RECLAIM | FLAG_DL_OVERRUN | FLAG_KEEP_ALL | FLAG_UTIL_CLAMP;
/// `SCHED_FLAG_SUGOV` (`kernel/sched/sched.h`): kernel-internal. It passes the
/// `~(SCHED_FLAG_ALL | SCHED_FLAG_SUGOV)` mask and is then rejected for any
/// `user` caller, so it is `EINVAL` from a syscall but not an unknown flag.
pub const FLAG_SUGOV: u64 = 0x1000_0000;

/// `SCHED_GETATTR_FLAG_DL_DYNAMIC` (include/uapi/linux/sched.h:160) — the only
/// `sched_getattr` flag, and only on a `SCHED_DEADLINE` task.
pub const GETATTR_FLAG_DL_DYNAMIC: u64 = 0x01;

/// Linux `SCHED_CAPACITY_SCALE` — the uclamp upper bound.
pub const CAPACITY_SCALE: u32 = 1024;
/// `sysctl_sched_uclamp_util_min_rt_default` (`kernel/sched/core.c:1581`).
pub const UCLAMP_MIN_RT_DEFAULT: u32 = CAPACITY_SCALE;
/// Linux `MIN_NICE`.
pub const MIN_NICE: i32 = -20;
/// Linux `MAX_NICE`.
pub const MAX_NICE: i32 = 19;
/// The `-1` reset sentinel as it arrives in the `__u32` uclamp fields.
pub const UCLAMP_RESET: u32 = u32::MAX;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Decoded `struct sched_attr`, VER1 shape.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct SchedAttr {
    pub size: u32,
    pub policy: u32,
    pub flags: u64,
    pub nice: i32,
    pub priority: u32,
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
    pub util_min: u32,
    pub util_max: u32,
}

macro_rules! rd { ($b:expr, $off:expr, $t:ty) => {{
    let mut a = [0u8; core::mem::size_of::<$t>()];
    a.copy_from_slice(&$b[$off .. $off + core::mem::size_of::<$t>()]);
    <$t>::from_le_bytes(a)
}}; }

impl SchedAttr {
    /// Decode the 56-byte kernel-side buffer the copy-in protocol produced.
    /// # C: O(1)
    pub fn from_bytes(b: &[u8; KSIZE as usize]) -> Self {
        SchedAttr {
            size: rd!(b, OFF_SIZE, u32), policy: rd!(b, OFF_POLICY, u32),
            flags: rd!(b, OFF_FLAGS, u64), nice: rd!(b, OFF_NICE, i32),
            priority: rd!(b, OFF_PRIORITY, u32), runtime: rd!(b, OFF_RUNTIME, u64),
            deadline: rd!(b, OFF_DEADLINE, u64), period: rd!(b, OFF_PERIOD, u64),
            util_min: rd!(b, OFF_UTIL_MIN, u32), util_max: rd!(b, OFF_UTIL_MAX, u32),
        }
    }

    /// Encode for `sched_getattr` copy-out.
    /// # C: O(1)
    pub fn to_bytes(&self) -> [u8; KSIZE as usize] {
        let mut b = [0u8; KSIZE as usize];
        b[OFF_SIZE..OFF_SIZE + 4].copy_from_slice(&self.size.to_le_bytes());
        b[OFF_POLICY..OFF_POLICY + 4].copy_from_slice(&self.policy.to_le_bytes());
        b[OFF_FLAGS..OFF_FLAGS + 8].copy_from_slice(&self.flags.to_le_bytes());
        b[OFF_NICE..OFF_NICE + 4].copy_from_slice(&self.nice.to_le_bytes());
        b[OFF_PRIORITY..OFF_PRIORITY + 4].copy_from_slice(&self.priority.to_le_bytes());
        b[OFF_RUNTIME..OFF_RUNTIME + 8].copy_from_slice(&self.runtime.to_le_bytes());
        b[OFF_DEADLINE..OFF_DEADLINE + 8].copy_from_slice(&self.deadline.to_le_bytes());
        b[OFF_PERIOD..OFF_PERIOD + 8].copy_from_slice(&self.period.to_le_bytes());
        b[OFF_UTIL_MIN..OFF_UTIL_MIN + 4].copy_from_slice(&self.util_min.to_le_bytes());
        b[OFF_UTIL_MAX..OFF_UTIL_MAX + 4].copy_from_slice(&self.util_max.to_le_bytes());
        b
    }
}

/// The copy-in shape `sched_copy_attr` + `copy_struct_from_user` produce for a
/// user-declared `attr->size`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CopyIn {
    /// `attr->size` after the `size == 0 -> SCHED_ATTR_SIZE_VER0` ABI quirk.
    pub size: u32,
    /// Bytes copied from the user struct; the remaining `KSIZE - copy` kernel
    /// bytes stay zero (`copy_struct_from_user`'s short-struct zero-fill).
    pub copy: u32,
    /// Bytes past `copy` in the user struct that must read as zero, else
    /// `E2BIG` (`check_zeroed_user`).
    pub tail: u32,
}

/// `sched_copy_attr()` size ladder. `Err(())` is the `err_size` label: write
/// `KSIZE` back to `uattr->size` and return `-E2BIG`.
/// # C: O(1)
pub fn copy_in_size(raw: u32) -> Result<CopyIn, ()> {
    // ABI compatibility quirk: a zero size means the first published struct.
    let size = if raw == 0 { SIZE_VER0 } else { raw };
    if size < SIZE_VER0 || size > MAX_SIZE { return Err(()); }
    let copy = if size < KSIZE { size } else { KSIZE };
    Ok(CopyIn { size, copy, tail: size - copy })
}

/// `sched_copy_attr()` post-copy rules: the util-clamp flags need a VER1-sized
/// struct, and `sched_nice` is CLAMPED rather than rejected.
/// # C: O(1)
pub fn finish_copy_in(attr: &mut SchedAttr, size: u32) -> Result<(), i64> {
    if attr.flags & FLAG_UTIL_CLAMP != 0 && size < SIZE_VER1 { return Err(err(Errno::Einval)); }
    if attr.nice < MIN_NICE { attr.nice = MIN_NICE; }
    if attr.nice > MAX_NICE { attr.nice = MAX_NICE; }
    Ok(())
}

/// The copy-out shape `sys_sched_getattr` + `copy_struct_to_user` produce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CopyOut {
    /// Value written into `kattr.size` — `min(usize, KSIZE)`.
    pub reported: u32,
    /// Bytes of the encoded struct copied out.
    pub copy: u32,
    /// Bytes past `copy` in the user struct that are zeroed (`clear_user`).
    pub zero: u32,
}

/// `sys_sched_getattr()` argument ladder: `usize` outside
/// `[SCHED_ATTR_SIZE_VER0, PAGE_SIZE]` is `-EINVAL` — never `-E2BIG`.
/// # C: O(1)
pub fn copy_out_size(user_size: u32) -> Result<CopyOut, i64> {
    if user_size < SIZE_VER0 || user_size > MAX_SIZE { return Err(err(Errno::Einval)); }
    let copy = if user_size < KSIZE { user_size } else { KSIZE };
    Ok(CopyOut { reported: copy, copy, zero: user_size - copy })
}

/// Linux `uclamp_validate()`. `cur_*` are the task's live `uclamp_req[].value`.
///
/// The signed comparison is Linux's, not a typo: `int util_min =
/// attr->sched_util_min` reinterprets the `__u32` field, so the `(u32)-1` reset
/// sentinel — and every value with bit 31 set — passes the range test while
/// `1025` does not.
/// # C: O(1)
pub fn uclamp_validate(attr: &SchedAttr, cur_min: u32, cur_max: u32) -> Result<(), i64> {
    let limit = CAPACITY_SCALE as i32 + 1;
    let mut util_min = cur_min as i32;
    let mut util_max = cur_max as i32;
    if attr.flags & FLAG_UTIL_CLAMP_MIN != 0 {
        util_min = attr.util_min as i32;
        if util_min.wrapping_add(1) > limit { return Err(err(Errno::Einval)); }
    }
    if attr.flags & FLAG_UTIL_CLAMP_MAX != 0 {
        util_max = attr.util_max as i32;
        if util_max.wrapping_add(1) > limit { return Err(err(Errno::Einval)); }
    }
    if util_min != -1 && util_max != -1 && util_min > util_max { return Err(err(Errno::Einval)); }
    Ok(())
}

/// One task's `uclamp_req[clamp_id]`: the requested value plus Linux's
/// `user_defined` bit, which decides whether a class change resets it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UclampSe { pub value: u32, pub user_defined: bool }

/// Linux `uclamp_reset()` + `__setscheduler_uclamp()` for one clamp id.
/// Runs on EVERY `__sched_setscheduler`, not only on a util-clamp request:
/// a non-user-defined clamp is reset to the class default each time.
/// # C: O(1)
pub fn uclamp_apply(attr: &SchedAttr, is_min: bool, cur: UclampSe, new_policy_is_rt: bool) -> UclampSe {
    let (flag, requested) = if is_min { (FLAG_UTIL_CLAMP_MIN, attr.util_min) }
                            else      { (FLAG_UTIL_CLAMP_MAX, attr.util_max) };
    let reset = (attr.flags & FLAG_UTIL_CLAMP == 0 && !cur.user_defined)
        || (attr.flags & flag != 0 && requested == UCLAMP_RESET);
    let mut out = cur;
    if reset {
        let value = if is_min {
            if new_policy_is_rt { UCLAMP_MIN_RT_DEFAULT } else { 0 }
        } else { CAPACITY_SCALE };
        out = UclampSe { value, user_defined: false };
    }
    if attr.flags & FLAG_UTIL_CLAMP == 0 { return out; }
    if attr.flags & flag != 0 && requested != UCLAMP_RESET {
        out = UclampSe { value: requested, user_defined: true };
    }
    out
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "sched_attr/tests.rs"]
mod tests;
