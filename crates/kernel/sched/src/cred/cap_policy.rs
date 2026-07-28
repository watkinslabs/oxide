// Pure decision logic for `capget(2)` / `capset(2)` — no user memory, no
// `current()`, no cfg gating, so hosted `cargo test` proves it. `caps.rs` is
// the marshalling shell that reads the header, resolves the target, and calls
// in here. Linux sources: `kernel/capability.c` (`cap_validate_magic`,
// `SYSCALL_DEFINE2(capget)`, `SYSCALL_DEFINE2(capset)`, `mk_kernel_cap`) and
// `security/commoncap.c` (`cap_capset`, `cap_inh_is_capped`).

use syscall::errno::Errno;

/// Linux `_LINUX_CAPABILITY_VERSION_{1,2,3}` magics
/// (`include/uapi/linux/capability.h`). v2 is deprecated but carries the same
/// two-block layout as v3, which is why `cap_validate_magic` falls through.
pub const CAPV1: u32 = 0x1998_0330;
pub const CAPV2: u32 = 0x2007_1026;
pub const CAPV3: u32 = 0x2008_0522;

/// Linux `CAP_LAST_CAP` == `CAP_CHECKPOINT_RESTORE`
/// (`include/uapi/linux/capability.h`).
pub const CAP_LAST_CAP: u32 = 40;

/// Linux `CAP_VALID_MASK` (`include/linux/capability.h`):
/// `BIT_ULL(CAP_LAST_CAP + 1) - 1`. Every set entering the kernel through
/// `capset` is masked with this by `mk_kernel_cap`, so undefined high bits are
/// dropped silently rather than rejected — a `capset` that writes `~0` into a
/// full-capability root task succeeds on Linux.
pub const CAP_VALID_MASK: u64 = (1u64 << (CAP_LAST_CAP + 1)) - 1;

/// `CAP_SETPCAP` bit position. Duplicated from `task::cap` to keep this module
/// dependency-free; the two are asserted equal in `tests`.
const SETPCAP_BIT: u32 = 8;

/// Number of `__user_cap_data_struct` blocks for each version
/// (`_LINUX_CAPABILITY_U32S_1` = 1, `_LINUX_CAPABILITY_U32S_3` = 2).
/// # C: O(1)
pub fn cap_data_blocks(ver: u32) -> Option<usize> {
    match ver {
        CAPV1 => Some(1),
        CAPV2 | CAPV3 => Some(2),
        _ => None,
    }
}

/// What `capget` does after validating the header magic, before it ever looks
/// at the target task. Linux `SYSCALL_DEFINE2(capget)`:
///
/// ```text
/// ret = cap_validate_magic(header, &tocopy);          // bad magic: writes
///                                                     // back V3, ret=-EINVAL
/// if ((dataptr == NULL) || (ret != 0))
///         return ((dataptr == NULL) && (ret == -EINVAL)) ? 0 : ret;
/// ```
///
/// So a NULL `dataptr` is a *version probe* and always succeeds — including
/// when the magic was wrong, which is precisely libcap's probe sequence — and
/// it returns before `cap_get_target_pid`, so the pid in the header is never
/// resolved. Returning EINVAL to a probe, or ESRCH because the probe named a
/// pid that no longer exists, both break the caller at its first call.
#[derive(Debug, PartialEq, Eq)]
pub enum CapgetEarly {
    /// Magic was bad: write V3 back to the header, then return this.
    RewriteVersion(i64),
    /// Magic was good and `dataptr` is NULL: succeed without touching the target.
    Ok,
    /// Magic was good and `dataptr` is set: proceed with `n` data blocks.
    Proceed(usize),
}

/// # C: O(1)
pub fn capget_early(ver: u32, datap: u64) -> CapgetEarly {
    match cap_data_blocks(ver) {
        None => CapgetEarly::RewriteVersion(if datap == 0 { 0 } else { -(Errno::Einval.as_i32() as i64) }),
        Some(_) if datap == 0 => CapgetEarly::Ok,
        Some(n) => CapgetEarly::Proceed(n),
    }
}

/// The caller's pre-`capset` capability state, as `cap_capset` reads it off
/// `old` (`security/commoncap.c`).
#[derive(Copy, Clone, Debug)]
pub struct CapsetOld {
    pub effective:   u64,
    pub permitted:   u64,
    pub inheritable: u64,
    pub bounding:    u64,
    pub ambient:     u64,
}

/// The capability sets `capset` installs when [`capset_check`] admits it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapsetNew {
    pub effective:   u64,
    pub permitted:   u64,
    pub inheritable: u64,
    pub ambient:     u64,
}

/// Linux `cap_capset` — the whole admission policy, verbatim in order:
///
/// ```text
/// if (cap_inh_is_capped() && !subset(I, old->I | old->P))  return -EPERM;
/// if (!subset(I, old->I | old->bset))                      return -EPERM;
/// if (!subset(P, old->P))                                  return -EPERM;
/// if (!subset(E, P))                                       return -EPERM;
/// new->ambient = ambient & P & I;
/// ```
///
/// Two things this is NOT, both of which we had wrong:
///   * it is **not** `I ⊆ (old->I | old->P) & bset`. The bounding-set test
///     unions `old->I` with the bounding set, so an inheritable bit the task
///     already holds survives a later `PR_CAPBSET_DROP` of that same bit —
///     `systemd`'s `CapabilityBoundingSet=` + `AmbientCapabilities=` order
///     depends on that.
///   * `cap_inh_is_capped()` is false for a task holding `CAP_SETPCAP` in
///     effect, which *removes* the `old->I | old->P` restriction entirely and
///     lets such a task raise any inheritable bit inside the bounding set.
///
/// Raw user sets are masked with [`CAP_VALID_MASK`] first (Linux
/// `mk_kernel_cap`), so undefined high bits never reach the subset tests.
/// # C: O(1)
pub fn capset_check(old: CapsetOld, raw_eff: u64, raw_perm: u64, raw_inh: u64)
    -> Result<CapsetNew, Errno>
{
    let effective   = raw_eff  & CAP_VALID_MASK;
    let permitted   = raw_perm & CAP_VALID_MASK;
    let inheritable = raw_inh  & CAP_VALID_MASK;
    let has_setpcap = (old.effective >> SETPCAP_BIT) & 1 == 1;
    if !has_setpcap && inheritable & !(old.inheritable | old.permitted) != 0 {
        return Err(Errno::Eperm);
    }
    if inheritable & !(old.inheritable | old.bounding) != 0 { return Err(Errno::Eperm); }
    if permitted & !old.permitted != 0 { return Err(Errno::Eperm); }
    if effective & !permitted != 0 { return Err(Errno::Eperm); }
    Ok(CapsetNew { effective, permitted, inheritable,
        ambient: old.ambient & permitted & inheritable })
}

#[cfg(test)]
mod tests;
