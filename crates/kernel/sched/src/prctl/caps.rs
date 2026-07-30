// Capability-set `prctl(2)` options — Linux `security/commoncap.c`
// `cap_task_prctl`, which runs from `security_task_prctl` BEFORE the
// `kernel/sys.c` switch and owns PR_CAPBSET_*, PR_{GET,SET}_SECUREBITS,
// PR_{GET,SET}_KEEPCAPS and PR_CAP_AMBIENT.
//
// PR_CAPBSET_READ capability-number validation is in `decide`.
// PR_CAPBSET_DROP retains the raw number here because Linux
// `security/commoncap.c::cap_prctl_drop` checks CAP_SETPCAP first, then
// `cap_valid`, then commits the credential change.

use core::sync::atomic::Ordering;
use syscall::errno::Errno;

use super::decide::Ambient;
use super::uapi::CAP_LAST_CAP;
use crate::task::creds::securebits;
use crate::task::Task;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `PR_CAPBSET_READ` — `!!cap_raised(old->cap_bset, arg2)`, returned as the
/// syscall VALUE. # C: O(1)
pub fn capbset_read(cur: &Task, cap: u32) -> i64 {
    ((cur.creds.cap_bounding.load(Ordering::Acquire) >> cap) & 1) as i64
}

fn capbset_drop_check(has_setpcap: bool, cap: u64) -> Result<u32, Errno> {
    if !has_setpcap { return Err(Errno::Eperm); }
    if cap > CAP_LAST_CAP { return Err(Errno::Einval); }
    Ok(cap as u32)
}

/// `PR_CAPBSET_DROP` — Linux `security/commoncap.c::cap_prctl_drop` checks
/// CAP_SETPCAP before validating the raw capability number. # C: O(1)
pub fn capbset_drop(cur: &Task, cap: u64) -> i64 {
    let cap = match capbset_drop_check(cur.has_cap(crate::cap::SETPCAP), cap) {
        Ok(cap) => cap,
        Err(e) => return err(e),
    };
    cur.creds.cap_bounding.fetch_and(!(1u64 << cap), Ordering::AcqRel);
    0
}

/// `PR_GET_KEEPCAPS` — `!!issecure(SECURE_KEEP_CAPS)`. # C: O(1)
pub fn get_keepcaps(cur: &Task) -> i64 {
    ((cur.creds.securebits.load(Ordering::Acquire) & securebits::SECBIT_KEEP_CAPS) != 0) as i64
}

/// `PR_SET_KEEPCAPS` — EPERM once `SECBIT_KEEP_CAPS_LOCKED` is set. # C: O(1)
pub fn set_keepcaps(cur: &Task, on: bool) -> i64 {
    let old = cur.creds.securebits.load(Ordering::Acquire);
    if (old & securebits::SECBIT_KEEP_CAPS_LOCKED) != 0 { return err(Errno::Eperm); }
    let new = if on { old | securebits::SECBIT_KEEP_CAPS }
        else { old & !securebits::SECBIT_KEEP_CAPS };
    cur.creds.securebits.store(new, Ordering::Release);
    0
}

/// `PR_GET_SECUREBITS` — `old->securebits`, returned as the syscall VALUE.
/// # C: O(1)
pub fn get_securebits(cur: &Task) -> i64 {
    cur.creds.securebits.load(Ordering::Acquire) as i64
}

/// `PR_SET_SECUREBITS` — no changing locked bits, no unlocking locks, no
/// unsupported bits, then CAP_SETPCAP. Every failure is EPERM, including the
/// out-of-range case (Linux's `arg2 & ~(SECURE_ALL_LOCKS | SECURE_ALL_BITS)`
/// arm, which a 64-bit `arg2` reaches whenever the high half is non-zero).
/// systemd applies per-service securebits in its exec child, so an EINVAL
/// here would abort the spawn at step SECUREBITS.
/// # C: O(1)
pub fn set_securebits(cur: &Task, requested: u64) -> i64 {
    if requested > u32::MAX as u64 { return err(Errno::Eperm); }
    let requested = requested as u32;
    let old = cur.creds.securebits.load(Ordering::Acquire);
    if !securebits::replacement_is_allowed(old, requested) { return err(Errno::Eperm); }
    if !cur.has_cap(crate::cap::SETPCAP) { return err(Errno::Eperm); }
    cur.creds.securebits.store(requested, Ordering::Release);
    0
}

/// `PR_CAP_AMBIENT` — manage the per-task ambient set. systemd's exec path
/// always calls CLEAR_ALL when applying a service's ambient set, so an EINVAL
/// here aborts every service spawn.
/// # C: O(1)
pub fn cap_ambient(cur: &Task, op: Ambient) -> i64 {
    match op {
        Ambient::ClearAll => { cur.creds.cap_ambient.store(0, Ordering::Release); 0 }
        Ambient::IsSet(cap) =>
            ((cur.creds.cap_ambient.load(Ordering::Acquire) >> cap) & 1) as i64,
        Ambient::Raise(cap) => {
            // Linux: the cap must be in BOTH permitted and inheritable, and
            // SECBIT_NO_CAP_AMBIENT_RAISE must be clear, else EPERM.
            let bit = 1u64 << cap;
            let perm = cur.creds.cap_permitted.load(Ordering::Acquire);
            let inh  = cur.creds.cap_inheritable.load(Ordering::Acquire);
            let sb   = cur.creds.securebits.load(Ordering::Acquire);
            if (perm & bit) == 0 || (inh & bit) == 0
                || (sb & securebits::SECBIT_NO_CAP_AMBIENT_RAISE) != 0 {
                return err(Errno::Eperm);
            }
            cur.creds.cap_ambient.fetch_or(bit, Ordering::AcqRel);
            0
        }
        Ambient::Lower(cap) => {
            cur.creds.cap_ambient.fetch_and(!(1u64 << cap), Ordering::AcqRel);
            0
        }
    }
}

/// `PR_GET_SECCOMP` — Linux returns `current->seccomp.mode` verbatim, so
/// SECCOMP_MODE_STRICT (1) and SECCOMP_MODE_FILTER (2) are distinguishable.
/// # C: O(1)
pub fn get_seccomp(cur: &Task) -> i64 {
    cur.seccomp_mode.load(Ordering::Acquire) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capbset_drop_permission_precedes_cap_validity() {
        for cap in [0, CAP_LAST_CAP, CAP_LAST_CAP + 1, 63, 64, u64::MAX] {
            assert_eq!(capbset_drop_check(false, cap), Err(Errno::Eperm));
        }
    }

    #[test]
    fn capbset_drop_validates_after_permission() {
        assert_eq!(capbset_drop_check(true, 0), Ok(0));
        assert_eq!(capbset_drop_check(true, CAP_LAST_CAP),
                   Ok(CAP_LAST_CAP as u32));
        for cap in [CAP_LAST_CAP + 1, 63, 64, u64::MAX] {
            assert_eq!(capbset_drop_check(true, cap), Err(Errno::Einval));
        }
    }
}
