// Real impls for the previous compat silent-0 tail: kcmp, NUMA
// family, process_madvise / process_mrelease.
//
// Linux behavior in one node:
//   - kcmp(pid1,pid2,type,idx1,idx2): real comparison of resource
//     pointers (-1=less, 0=equal, 1=greater). v1 compares Task fields
//     directly when both pids exist; ESRCH otherwise.
//   - set_mempolicy / get_mempolicy / mbind / migrate_pages /
//     move_pages / set_mempolicy_home_node: validate args; on a
//     single-node UMA system Linux returns success because the
//     "policy applied" outcome is trivially true.
//   - process_madvise(iov, advice): walk the iov, validate each
//     segment is in user range; same advise semantics as madvise.
//   - process_mrelease(pidfd, flags): validate pidfd, return 0.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

const MPOL_DEFAULT:    u32 = 0;
const MPOL_PREFERRED:  u32 = 1;
const MPOL_BIND:       u32 = 2;
const MPOL_INTERLEAVE: u32 = 3;
const MPOL_LOCAL:      u32 = 4;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Tail dispatch for the previously-compat tail (pkey, kcmp, NUMA,
/// process_madvise/mrelease).
/// # C: O(1)
pub fn dispatch(nr: u64, args: &SyscallArgs) -> i64 {
    use crate::syscall_nrs::*;
    match nr {
        NR_PKEY_ALLOC                => kernel_sys_pkey_alloc(args),
        NR_PKEY_FREE                 => kernel_sys_pkey_free(args),
        NR_PKEY_MPROTECT             => kernel_sys_pkey_mprotect(args),
        NR_KCMP                      => kernel_sys_kcmp(args),
        NR_SET_MEMPOLICY             => kernel_sys_set_mempolicy(args),
        NR_GET_MEMPOLICY             => kernel_sys_get_mempolicy(args),
        NR_MBIND                     => kernel_sys_mbind(args),
        NR_SET_MEMPOLICY_HOME_NODE   => kernel_sys_set_mempolicy_home_node(args),
        NR_MIGRATE_PAGES             => kernel_sys_migrate_pages(args),
        NR_MOVE_PAGES                => kernel_sys_move_pages(args),
        NR_PROCESS_MADVISE           => kernel_sys_process_madvise(args),
        NR_PROCESS_MRELEASE          => kernel_sys_process_mrelease(args),
        _                            => -(Errno::Enosys.as_i32() as i64),
    }
}

/// Per-process pkey bitmap. Linux MPK has 16 keys; key 0 is the
/// always-permitted default. v1 tracks allocations as a 16-bit
/// bitmap so glibc/musl probes get unique ids; PKRU enforcement
/// rides v2.x.
static PKEY_BITMAP: core::sync::atomic::AtomicU16
    = core::sync::atomic::AtomicU16::new(1);

/// # C: O(1)
pub fn kernel_sys_pkey_alloc(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let mut cur = PKEY_BITMAP.load(Ordering::Acquire);
    loop {
        let i = match (1..16).find(|i| cur & (1u16 << i) == 0) {
            Some(i) => i, None => return errno(Errno::Enospc),
        };
        let next = cur | (1u16 << i);
        match PKEY_BITMAP.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_)    => return i as i64,
            Err(now) => cur = now,
        }
    }
}
/// # C: O(1)
pub fn kernel_sys_pkey_free(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let key = args.a0 as i32;
    if !(1..16).contains(&key) { return errno(Errno::Einval); }
    let mut cur = PKEY_BITMAP.load(Ordering::Acquire);
    loop {
        if cur & (1u16 << key) == 0 { return errno(Errno::Einval); }
        let next = cur & !(1u16 << key);
        match PKEY_BITMAP.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_)    => return 0,
            Err(now) => cur = now,
        }
    }
}
/// # C: O(1) + mprotect cost
pub fn kernel_sys_pkey_mprotect(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let key = args.a3 as i32;
    if key < 0 || key >= 16 { return errno(Errno::Einval); }
    if PKEY_BITMAP.load(Ordering::Acquire) & (1u16 << key) == 0 {
        return errno(Errno::Einval);
    }
    crate::syscall_glue_proc::kernel_sys_mprotect(args)
}

/// fsync / fdatasync / syncfs / sync_file_range — validate fd then
/// no-op (RAM-backed v1 fs is always sync; phase 7b adds JBD2).
/// # C: O(1)
pub fn kernel_sys_fsync(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match crate::sched::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; clone Arc.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    if fdt.get(fd).is_err() { return errno(Errno::Ebadf); }
    0
}

/// kcmp(2): compare two tasks' resources by pointer identity.
/// Returns 0/1/-1 (equal/greater/less); ESRCH for missing pids;
/// EINVAL for unknown type.
/// # C: O(1)
pub fn kernel_sys_kcmp(args: &SyscallArgs) -> i64 {
    let pid1 = args.a0 as u32;
    let pid2 = args.a1 as u32;
    let ty   = args.a2 as u32;
    let idx1 = args.a3 as u64;
    let idx2 = args.a4 as u64;
    if ty > 7 { return errno(Errno::Einval); }
    let t1 = match crate::sched::registry::lookup(pid1) {
        Some(t) => t, None => return errno(Errno::Esrch),
    };
    let t2 = match crate::sched::registry::lookup(pid2) {
        Some(t) => t, None => return errno(Errno::Esrch),
    };
    // KCMP_FILE = 0: compare File at fd idx1 in t1 vs fd idx2 in t2.
    let cmp = match ty {
        0 => {
            // SAFETY: fd_table slot single-mutator per `13§5`; snapshot via Arc clone.
            unsafe {
                let f1 = (*t1.fd_table.get()).as_ref().and_then(|t| t.get(idx1 as i32).ok());
                let f2 = (*t2.fd_table.get()).as_ref().and_then(|t| t.get(idx2 as i32).ok());
                ptr_cmp(f1.map(|f| alloc::sync::Arc::as_ptr(&f) as usize),
                        f2.map(|f| alloc::sync::Arc::as_ptr(&f) as usize))
            }
        },
        // KCMP_FILES = 1: compare fd_table identity.
        1 => {
            // SAFETY: fd_table slot single-mutator per `13§5`; pointer identity is the resource id.
            unsafe {
                let p1 = (*t1.fd_table.get()).as_ref().map(|t| alloc::sync::Arc::as_ptr(t) as usize);
                let p2 = (*t2.fd_table.get()).as_ref().map(|t| alloc::sync::Arc::as_ptr(t) as usize);
                ptr_cmp(p1, p2)
            }
        },
        // KCMP_VM = 2: address-space identity.
        2 => {
            // SAFETY: mm slot single-mutator per `13§5`; pointer identity = AS resource id.
            unsafe {
                let p1 = t1.mm_ref().map(|m| alloc::sync::Arc::as_ptr(m) as usize);
                let p2 = t2.mm_ref().map(|m| alloc::sync::Arc::as_ptr(m) as usize);
                ptr_cmp(p1, p2)
            }
        },
        // KCMP_FS=3 / KCMP_SIGHAND=4 / KCMP_IO=5 / KCMP_SYSVSEM=6:
        // v1 ties these to the task identity since we don't yet
        // share these resources across CLONE_FS / CLONE_SIGHAND.
        _ => ptr_cmp(Some(pid1 as usize), Some(pid2 as usize)),
    };
    cmp as i64
}

fn ptr_cmp(a: Option<usize>, b: Option<usize>) -> i64 {
    match (a, b) {
        (Some(x), Some(y)) if x == y => 0,
        (Some(x), Some(y)) if x  < y => -1,
        (Some(_), Some(_))           => 1,
        (None,    None)              => 0,
        (None,    Some(_))           => -1,
        (Some(_), None)              => 1,
    }
}

/// set_mempolicy(mode, nodemask, maxnode).
/// # C: O(1)
pub fn kernel_sys_set_mempolicy(args: &SyscallArgs) -> i64 {
    let mode = args.a0 as u32;
    if mode > MPOL_LOCAL { return errno(Errno::Einval); }
    0
}

/// get_mempolicy(mode_out, nodemask_out, maxnode, addr, flags).
/// # C: O(1)
pub fn kernel_sys_get_mempolicy(args: &SyscallArgs) -> i64 {
    let mode_out = args.a0;
    if mode_out != 0 {
        if mode_out >= hal::USER_VA_END { return errno(Errno::Efault); }
        // SAFETY: validated < USER_VA_END; aligned u32 store.
        unsafe { core::ptr::write_volatile(mode_out as *mut u32, MPOL_DEFAULT); }
    }
    0
}

/// mbind(addr, len, mode, nodemask, maxnode, flags).
/// # C: O(1)
pub fn kernel_sys_mbind(args: &SyscallArgs) -> i64 {
    let mode = args.a2 as u32;
    if mode > MPOL_LOCAL { return errno(Errno::Einval); }
    0
}

/// set_mempolicy_home_node(start, len, home_node, flags).
/// # C: O(1)
pub fn kernel_sys_set_mempolicy_home_node(args: &SyscallArgs) -> i64 {
    let home = args.a2 as i32;
    if home != 0 && home != -1 { return errno(Errno::Einval); }
    0
}

/// migrate_pages(pid, maxnode, old, new).
/// # C: O(1)
pub fn kernel_sys_migrate_pages(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    if pid != 0 && crate::sched::registry::lookup(pid).is_none() {
        return errno(Errno::Esrch);
    }
    0
}

/// move_pages(pid, count, pages, nodes, status, flags).
/// # C: O(N=count, capped 4096)
pub fn kernel_sys_move_pages(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    if pid != 0 && crate::sched::registry::lookup(pid).is_none() {
        return errno(Errno::Esrch);
    }
    let count = args.a1 as usize;
    let status = args.a4;
    if status != 0 && count > 0 {
        if status >= hal::USER_VA_END { return errno(Errno::Efault); }
        // Each page is "on node 0" in our single-node world.
        for i in 0..count.min(4096) {
            // SAFETY: status validated < USER_VA_END; bounded count loop; aligned i32 store into caller's AS.
            unsafe {
                core::ptr::write_volatile((status + (i*4) as u64) as *mut i32, 0);
            }
        }
    }
    0
}

/// process_madvise(pidfd, iov, iovcnt, advice, flags).
/// # C: O(N=iovcnt, capped 64)
pub fn kernel_sys_process_madvise(args: &SyscallArgs) -> i64 {
    let iov = args.a1;
    let cnt = args.a2 as usize;
    if cnt == 0 { return 0; }
    if iov == 0 || iov >= hal::USER_VA_END { return errno(Errno::Efault); }
    // Validate first iovec entry's pointer falls in user range; same
    // advise-only semantics as madvise once validated.
    for i in 0..cnt.min(64) {
        let p = iov + (i as u64) * 16;
        if p >= hal::USER_VA_END { return errno(Errno::Efault); }
        // SAFETY: validated p < USER_VA_END; 8-byte aligned read of iovec.iov_base from caller's AS.
        let base = unsafe { core::ptr::read_volatile(p as *const u64) };
        if base != 0 && base >= hal::USER_VA_END { return errno(Errno::Efault); }
    }
    0
}

/// reboot(magic1, magic2, cmd, arg) per Linux reboot(2).
/// Validates magic numbers, requires CAP_SYS_BOOT, then dispatches
/// through the `power` crate. RESTART/POWER_OFF/HALT are irreversible
/// and never return; CAD_ON/CAD_OFF return 0; KEXEC returns EINVAL.
/// # C: O(1)
pub fn kernel_sys_reboot(args: &SyscallArgs) -> i64 {
    let magic1 = args.a0 as u32;
    let magic2 = args.a1 as u32;
    let c      = args.a2 as u32;
    if !power::check_magic(magic1, magic2) { return errno(Errno::Einval); }
    let cur = match crate::sched::current() { Some(c) => c, None => return errno(Errno::Eperm) };
    use core::sync::atomic::Ordering;
    if (cur.creds.cap_effective.load(Ordering::Acquire) >> sched::cap::SYS_BOOT) & 1 == 0 {
        return errno(Errno::Eperm);
    }
    // SAFETY: capability + magic validated above; cmd is irreversible per power(2) contract.
    match unsafe { power::cmd(c) } {
        Ok(())                       => 0,
        Err(power::Error::Inval)     => errno(Errno::Einval),
        Err(power::Error::Perm)      => errno(Errno::Eperm),
        Err(power::Error::Io)        => errno(Errno::Eio),
    }
}

/// process_mrelease(pidfd, flags).
/// # C: O(1)
pub fn kernel_sys_process_mrelease(args: &SyscallArgs) -> i64 {
    let cur = match crate::sched::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; clone Arc.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    if fdt.get(args.a0 as i32).is_err() { return errno(Errno::Ebadf); }
    0
}
