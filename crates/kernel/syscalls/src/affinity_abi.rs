// `sched_setaffinity(2)`/`sched_getaffinity(2)` cpumask ABI + decision core —
// Linux's `sys_sched_setaffinity`, `get_user_cpu_mask`,
// `sched_setaffinity`, `__sched_setaffinity`, `sys_sched_getaffinity`,
// `sched_getaffinity`, `check_same_owner`, and `cpumask_size`.
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: slots 203/204 are
// kernel-only, so the `len`-in-BYTES rules, the return-value contract glibc's
// `sched_getaffinity` loop depends on, and the EPERM-vs-ESRCH-vs-EINVAL order
// were unreachable from `cargo test`. They live here; the slots stay thin
// shims (docs/53).
//
// Module manifest:
//   this file  — cpumask sizing, user-buffer decode, permission rule, the
//                ordered set/get decisions.
//   tests/     — hosted unit tests (`affinity_abi/tests.rs`).

use syscall::errno::Errno;
use cpu::CpuMask;
use cpu::mask::CPU_MASK_WORDS;

#[cfg(test)]
mod tests;

/// `nr_cpu_ids` — the number of CPU ids this kernel can address. `cpu::MAX_CPUS`
/// is the current logical CPU admission limit.
pub const NR_CPU_IDS: usize = cpu::MAX_CPUS;

/// Linux `cpumask_size()` = `bitmap_size(nr_cpu_ids)` =
/// `ALIGN(nr_cpu_ids, BITS_PER_LONG) / BITS_PER_BYTE`. This is the byte count
/// `sched_getaffinity(2)` returns and the ceiling `sched_setaffinity(2)` copies.
pub const CPUMASK_SIZE: usize = (NR_CPU_IDS + 7) / 8;

/// `sizeof(unsigned long)` — `sched_getaffinity` rejects any `len` that is not
/// a multiple of it.
pub const BYTES_PER_LONG: usize = 8;

/// Linux `get_user_cpu_mask`: `len < cpumask_size()` clears the mask and copies
/// only `len` bytes; `len > cpumask_size()` clamps to `cpumask_size()`. There is
/// NO minimum-length check on the SET side — `sched_setaffinity(pid, 4, p)` is
/// legal and reads four bytes. Rejecting a short `len` with EINVAL (as a
/// symmetric-with-get implementation would) breaks every caller using a
/// `cpu_set_t` narrower than the kernel's mask. # C: O(1)
pub fn set_copy_len(len: usize) -> usize { if len > CPUMASK_SIZE { CPUMASK_SIZE } else { len } }

/// Assemble a cpumask from the little-endian bytes `get_user_cpu_mask` copied.
/// Bytes the caller did not supply read as zero (Linux `cpumask_clear` first).
/// # C: O(len)
pub fn mask_from_bytes(bytes: &[u8]) -> CpuMask {
    let mut words = [0u64; CPU_MASK_WORDS];
    let mut i = 0;
    while i < bytes.len() && i < CPUMASK_SIZE {
        words[i / 8] |= (bytes[i] as u64) << ((i % 8) * 8);
        i += 1;
    }
    CpuMask::from_words(&words)
}

/// Encode a CPU mask in the little-endian byte order used by affinity syscalls.
/// # C: O(words)
pub fn mask_to_bytes(mask: CpuMask) -> [u8; CPUMASK_SIZE] {
    let mut out = [0u8; CPUMASK_SIZE];
    let words = mask.as_words();
    let mut i = 0;
    while i < CPUMASK_SIZE {
        out[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
        i += 1;
    }
    out
}

/// Linux `sys_sched_getaffinity` entry checks, in order:
///
/// ```text
/// if ((len * BITS_PER_BYTE) < nr_cpu_ids) return -EINVAL;
/// if (len & (sizeof(unsigned long)-1))    return -EINVAL;
/// ```
///
/// On success returns `min(len, cpumask_size())` — the byte count the syscall
/// returns. glibc's `sched_getaffinity` zero-fills `cpuset[ret..cpusetsize]`
/// from it, and `__get_nprocs` grows its buffer until the call stops returning
/// EINVAL, so returning `0` on success (instead of the byte count) makes glibc
/// report zero CPUs. # C: O(1)
pub fn getaffinity_retlen(len: usize) -> Result<usize, Errno> {
    if len.saturating_mul(8) < NR_CPU_IDS { return Err(Errno::Einval); }
    if len & (BYTES_PER_LONG - 1) != 0 { return Err(Errno::Einval); }
    Ok(if len > CPUMASK_SIZE { CPUMASK_SIZE } else { len })
}

/// Linux `sched_getaffinity`: report `p->cpus_mask & cpu_active_mask`, so a
/// CPU that is offline never shows up as usable even though the stored mask
/// still names it. # C: O(words)
pub fn reported_mask(cpus_allowed: CpuMask, active: CpuMask) -> CpuMask { cpus_allowed.intersect(active) }

/// Linux `check_same_owner()` + the `CAP_SYS_NICE` override in
/// `sched_setaffinity`: the caller may repin a task it owns, and `CAP_SYS_NICE`
/// lifts the ownership requirement. Without this a task can repin any other
/// task on the system, root's included. # C: O(1)
pub fn setaffinity_permitted(same_owner: bool, cap_sys_nice: bool) -> bool {
    same_owner || cap_sys_nice
}

/// Linux `__sched_setaffinity`: `cpumask_and(new_mask, ctx->new_mask,
/// cpus_allowed)` where `cpus_allowed` is `cpuset_cpus_allowed(p)`. The mask
/// STORED is the requested one narrowed by the cpuset — NOT narrowed by the
/// active mask, so a CPU that is merely offline stays in the mask and becomes
/// usable again the moment it comes online.
///
/// The composition rule itself is owned by `sched::affinity` — the same owner
/// the cgroup `cpuset.cpus` writer uses, under the other [`MaskChange`] arm —
/// so the two writers of `cpus_allowed` cannot drift apart. # C: O(words)
pub fn effective_mask(want: CpuMask, cpuset: CpuMask) -> CpuMask {
    sched::affinity::compose(cpuset, want, sched::affinity::MaskChange::UserRequest)
}

/// Linux `__set_cpus_allowed_ptr_locked`:
/// `cpumask_any_and_distribute(new_mask, cpu_valid_mask) >= nr_cpu_ids` is
/// EINVAL — a mask naming no *active* CPU is rejected rather than stored, since
/// the task could never be scheduled again. # C: O(1)
pub fn admits_mask(eff: CpuMask, active: CpuMask) -> Result<(), Errno> {
    if eff.intersect(active).is_empty() { return Err(Errno::Einval); }
    Ok(())
}

/// The ordered `sched_setaffinity` decision, after the target has been resolved
/// (ESRCH) and the user mask copied in (EFAULT). Linux order, from
/// `sched_setaffinity()`:
///
/// ```text
/// if (!p)                          return -ESRCH;
/// if (p->flags & PF_NO_SETAFFINITY) return -EINVAL;
/// if (!check_same_owner(p) && !ns_capable(.., CAP_SYS_NICE)) return -EPERM;
/// ... __sched_setaffinity(): new = in_mask & cpuset; empty vs active -> -EINVAL
/// ```
///
/// Returns the mask to store on success. Ordering matters to callers that
/// probe: an implementation that reports EINVAL for an empty mask before
/// checking ownership tells an unprivileged prober that the pid exists.
/// # C: O(1)
pub fn setaffinity_decide(want: CpuMask, cpuset: CpuMask, active: CpuMask, no_setaffinity: bool,
                          same_owner: bool, cap_sys_nice: bool) -> Result<CpuMask, Errno> {
    if no_setaffinity { return Err(Errno::Einval); }
    if !setaffinity_permitted(same_owner, cap_sys_nice) { return Err(Errno::Eperm); }
    let eff = effective_mask(want, cpuset);
    admits_mask(eff, active)?;
    Ok(eff)
}

/// Recompute `cpus_allowed` when a cgroup `cpuset.cpus` changes. The rule
/// itself lives with the fields it composes (`sched::affinity::compose`) so the
/// cgroup hook and this syscall cannot drift apart. The kernel-side caller is
/// `sched::cgroup`, which calls that same owner with the cpuset arm; this
/// wrapper exists for the hosted tests that pin the two arms against each
/// other and against this file's decision core. # C: O(words)
#[cfg(test)]
pub fn cpuset_recompute(cpuset: CpuMask, user: CpuMask) -> CpuMask {
    sched::affinity::compose(cpuset, user, sched::affinity::MaskChange::CpusetUpdate)
}
