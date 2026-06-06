// CPU-affinity syscalls (`sched_setaffinity`/`getaffinity`, slots
// 203/204) backed by `Task::cpus_allowed`. Split from proc.rs for the
// 1000-line cap (`08§7`). With real SMP (both arches `-smp 2`) the mask
// is honored by the load balancer (`balance_once` won't migrate a task
// to a CPU outside its mask); cgroup `cpuset.cpus` rewrites it too.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// Resolve the affinity target task as an `Arc`: `pid==0` → current; else
/// the task with that global tid. None → ESRCH.
/// # C: O(1) registry lookup
fn affinity_target(pid: u32) -> Option<alloc::sync::Arc<sched::Task>> {
    let tid = if pid == 0 { sched::live::current()?.tid } else { pid };
    sched::live::registry::lookup(tid)
}

/// Bitmask of online CPUs (bit N set ⇔ CPU N online). Capped at 64.
/// # C: O(1)
fn online_cpu_mask() -> u64 {
    let n = (cpu::smp::online_count() as u32).min(64);
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

/// `sys_sched_getaffinity(pid, cpusetsize, mask)` — slot 204. Writes the
/// task's `cpus_allowed` bitmask (masked to online CPUs) into the user
/// buffer; returns the bytes written (8).
/// # C: O(1)
pub fn sys_sched_getaffinity(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (pid, cpusetsize, mask) = (args.a0 as u32, args.a1, args.a2);
    if mask == 0 || mask >= hal::USER_VA_END || cpusetsize < 8 {
        return -(syscall::errno::Errno::Einval.as_i32() as i64);
    }
    let t = match affinity_target(pid) { Some(t) => t, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64) };
    let m = t.cpus_allowed.load(Ordering::Acquire) & online_cpu_mask();
    // SAFETY: mask validated < USER_VA_END; cpusetsize >= 8 guarantees the 8-byte write fits; CPL=0 writes through caller's AS.
    unsafe { core::ptr::write_volatile(mask as *mut u64, m); }
    8
}

/// `sys_sched_setaffinity(pid, cpusetsize, mask)` — slot 203. Stores the
/// user mask (intersected with online CPUs) into the task's
/// `cpus_allowed`. EINVAL if the result is empty (Linux semantics).
/// # C: O(1)
pub fn sys_sched_setaffinity(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (pid, cpusetsize, mask) = (args.a0 as u32, args.a1, args.a2);
    if mask == 0 || mask >= hal::USER_VA_END || cpusetsize < 8 {
        return -(syscall::errno::Errno::Einval.as_i32() as i64);
    }
    // SAFETY: mask validated < USER_VA_END; 8-byte read within the user buffer (cpusetsize>=8); CPL=0 reads through caller's AS.
    let want = unsafe { core::ptr::read_volatile(mask as *const u64) };
    let eff = want & online_cpu_mask();
    if eff == 0 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let t = match affinity_target(pid) { Some(t) => t, None => return -(syscall::errno::Errno::Esrch.as_i32() as i64) };
    t.cpus_allowed.store(eff, Ordering::Release);
    0
}
