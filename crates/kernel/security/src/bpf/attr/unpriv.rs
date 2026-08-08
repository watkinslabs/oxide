// `kernel.unprivileged_bpf_disabled`: the cell, its one-way latch, and the
// permission a write to it demands.

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::errno::Errno;

/// `sysctl_unprivileged_bpf_disabled` value. Every distro this kernel
/// targets ships with unprivileged BPF off by default, so 2 is the matching
/// default here. Non-zero means MAP_CREATE and PROG_LOAD demand
/// `bpf_capable()`; element ops on an already-open map fd are never gated.
static UNPRIV_BPF_DISABLED: AtomicU32 = AtomicU32::new(2);

/// # C: O(1)
pub fn unpriv_bpf_disabled() -> bool { UNPRIV_BPF_DISABLED.load(Ordering::Relaxed) != 0 }

/// The knob's own value, for the `/proc/sys` leaf that reports it.
/// # C: O(1)
pub fn unpriv_bpf_disabled_value() -> u32 { UNPRIV_BPF_DISABLED.load(Ordering::Relaxed) }

/// # C: O(1)
pub fn set_unpriv_bpf_disabled(v: u32) { UNPRIV_BPF_DISABLED.store(v, Ordering::Relaxed); }

/// Admitted values for `kernel.unprivileged_bpf_disabled`.
pub const UNPRIV_BPF_BOUNDS: (i64, i64) = (0, 2);

/// What a write to `kernel.unprivileged_bpf_disabled` may do.
///
/// Only the administrative capability may write it at all. The value 1 is a
/// ONE-WAY latch: once unprivileged BPF has been switched off that way it can
/// never be switched back on for the life of the boot, which is the whole
/// point of the setting — an attacker who reaches root-equivalent code must
/// not be able to re-open the interface. The value 2 (the build-time default)
/// carries no latch, so an administrator can still choose the weaker setting
/// on a kernel that shipped with the stronger one.
/// # C: O(1)
pub fn unpriv_write_verdict(current: u32, new: i64, cap_sys_admin: bool)
    -> Result<u32, Errno>
{
    if !cap_sys_admin { return Err(Errno::Eperm); }
    if new < UNPRIV_BPF_BOUNDS.0 || new > UNPRIV_BPF_BOUNDS.1 { return Err(Errno::Einval); }
    if current == 1 && new != 1 { return Err(Errno::Eperm); }
    Ok(new as u32)
}

/// Apply a `/proc/sys` write, reading the writer's capability itself.
/// # C: O(1)
pub fn write_unpriv_bpf_disabled(new: i64) -> Result<(), Errno> {
    let cap = sched::current()
        .map(|c| c.creds.has_cap(sched::cap::SYS_ADMIN))
        .unwrap_or(false);
    let v = unpriv_write_verdict(unpriv_bpf_disabled_value(), new, cap)?;
    set_unpriv_bpf_disabled(v);
    Ok(())
}
