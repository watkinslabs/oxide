use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// Linux `_LINUX_CAPABILITY_VERSION_3` magic. v1 (32-bit caps) +
/// v2 (deprecated/buggy) accepted with single-u32 layout for
/// backwards compat; v3 is the current normal case.
const CAPV1: u32 = 0x1998_0330;
const CAPV2: u32 = 0x2007_1026;
const CAPV3: u32 = 0x2008_0522;

/// Number of `__user_cap_data_struct` blocks for each version.
fn cap_data_blocks(ver: u32) -> Option<usize> {
    match ver {
        CAPV1 => Some(1),
        CAPV2 | CAPV3 => Some(2),
        _ => None,
    }
}

/// Read a `__user_cap_header_struct` (8 bytes: u32 version, i32 pid).
/// # SAFETY: caller validated `hp` < USER_VA_END and the 8-byte tail
/// is in user memory; CPL=0 reads through caller's AS.
unsafe fn read_caphdr(hp: u64) -> Result<(u32, i32), i64> {
    if hp == 0
        || hp >= hal::USER_VA_END
        || hp.checked_add(8).map(|e| e > hal::USER_VA_END).unwrap_or(true)
    {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: hp validated < USER_VA_END with 8-byte tail in user range; CPL=0 reads through caller AS at 4-byte aligned u32/i32 fields.
    let ver = unsafe { core::ptr::read_volatile(hp as *const u32) };
    // SAFETY: same range validated above; pid lies at offset+4, still inside the validated 8-byte tail; CPL=0 read of i32 from caller AS.
    let pid = unsafe { core::ptr::read_volatile((hp + 4) as *const i32) };
    Ok((ver, pid))
}

/// Resolve a cap target by pid (0 = current) → Arc-or-stub of the
/// task's creds. Returns the loaded triple `(eff, perm, inh)`.
fn cap_load_target(pid: i32) -> Result<(u64, u64, u64), i64> {
    if pid < 0 {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    fn caps_of(c: &crate::Task) -> (u64, u64, u64) {
        (
            c.creds.cap_effective.load(Ordering::Acquire),
            c.creds.cap_permitted.load(Ordering::Acquire),
            c.creds.cap_inheritable.load(Ordering::Acquire),
        )
    }
    let esrch = -(Errno::Esrch.as_i32() as i64);
    if pid == 0 {
        return crate::live::current().map(caps_of).ok_or(esrch);
    }
    // `pid` is a namespace thread id (the caller's pid_ns) — a VPID.
    // Resolve via lookup_by_vpid, NOT the internal-tid registry.
    // systemd/libcap calls capget with its own getpid() (vpid 1); keying
    // on the internal tid missed it and returned ESRCH ("No such
    // process"), aborting every service spawn at the CAPABILITIES step.
    let v = pid as u32;
    if let Some(c) = crate::live::current() {
        if v == c.vtid.load(Ordering::Acquire) || v == c.vtgid.load(Ordering::Acquire) {
            return Ok(caps_of(c));
        }
    }
    match crate::live::registry::lookup_by_vpid(v).or_else(|| crate::live::registry::lookup(v)) {
        Some(t) => Ok(caps_of(&t)),
        None => Err(esrch),
    }
}

/// `sys_capget(hdrp, datap)` — slot 125. Reads the version+pid from
/// the header, looks up the target task, writes effective/permitted/
/// inheritable as N×{u32 effective, u32 permitted, u32 inheritable}
/// blocks (low32 of each u64 first, high32 second for v2/v3). When
/// `datap == NULL` only the version is updated to V3 + EINVAL is
/// returned per Linux when ver was unknown — used by libcap as a
/// version-probe pattern.
/// # C: O(1)
pub(super) fn sys_capget(args: &SyscallArgs) -> i64 {
    let hp = args.a0;
    let dp = args.a1;
    // SAFETY: read_caphdr validates the pointer range itself.
    let (ver, pid) = match unsafe { read_caphdr(hp) } {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    let nblocks = match cap_data_blocks(ver) {
        Some(n) => n,
        None => {
            // Version probe: libcap reads the magic, sees mismatch, retries with V3.
            // SAFETY: hp validated; CPL=0 write to caller AS.
            unsafe { core::ptr::write_volatile(hp as *mut u32, CAPV3) };
            return -(Errno::Einval.as_i32() as i64);
        }
    };
    let (eff, perm, inh) = match cap_load_target(pid) {
        Ok(t) => t,
        Err(rv) => return rv,
    };
    if dp == 0 {
        return 0;
    }
    let bytes_needed = nblocks * 12;
    if dp >= hal::USER_VA_END
        || dp
            .checked_add(bytes_needed as u64)
            .map(|e| e > hal::USER_VA_END)
            .unwrap_or(true)
    {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: dp validated; CPL=0 writes to caller AS; layout matches Linux UAPI.
    unsafe {
        let p = dp as *mut u32;
        core::ptr::write_volatile(p.add(0), eff as u32);
        core::ptr::write_volatile(p.add(1), perm as u32);
        core::ptr::write_volatile(p.add(2), inh as u32);
        if nblocks == 2 {
            core::ptr::write_volatile(p.add(3), (eff >> 32) as u32);
            core::ptr::write_volatile(p.add(4), (perm >> 32) as u32);
            core::ptr::write_volatile(p.add(5), (inh >> 32) as u32);
        }
    }
    0
}

/// `sys_capset(hdrp, datap)` — slot 126. Linux only allows capset
/// against the calling task (pid==0 or pid==tid). Permission rules:
///   * new permitted ⊆ old permitted
///   * new effective ⊆ new permitted
///   * new inheritable ⊆ old inheritable ∪ old permitted (intersected with bounding)
/// Root may freely shrink; raising bits beyond old_permitted is EPERM.
/// # C: O(1)
pub(super) fn sys_capset(args: &SyscallArgs) -> i64 {
    let hp = args.a0;
    let dp = args.a1;
    // SAFETY: read_caphdr validates hp range and reads u32 ver + i32 pid from caller AS at CPL=0; this call site only consumes the returned pair.
    let (ver, pid) = match unsafe { read_caphdr(hp) } {
        Ok(p) => p,
        Err(rv) => return rv,
    };
    let nblocks = match cap_data_blocks(ver) {
        Some(n) => n,
        None => {
            // SAFETY: hp validated < USER_VA_END by read_caphdr; the version slot is the first 4 bytes of the validated 8-byte tail, CPL=0 write to caller AS.
            unsafe { core::ptr::write_volatile(hp as *mut u32, CAPV3) };
            return -(Errno::Einval.as_i32() as i64);
        }
    };
    let cur = match crate::live::current() {
        Some(c) => c,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    // capset only targets the calling thread: pid 0, or the caller's own
    // id by internal tid OR namespace vpid (systemd/libcap passes its
    // getpid() vpid, not the internal tid).
    if pid != 0
        && pid as u32 != cur.tid
        && pid as u32 != cur.vtid.load(Ordering::Acquire)
        && pid as u32 != cur.vtgid.load(Ordering::Acquire)
    {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let bytes_needed = nblocks * 12;
    if dp == 0
        || dp >= hal::USER_VA_END
        || dp
            .checked_add(bytes_needed as u64)
            .map(|e| e > hal::USER_VA_END)
            .unwrap_or(true)
    {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: dp validated; CPL=0 reads from caller AS.
    let (new_eff, new_perm, new_inh) = unsafe {
        let p = dp as *const u32;
        let e0 = core::ptr::read_volatile(p.add(0)) as u64;
        let p0 = core::ptr::read_volatile(p.add(1)) as u64;
        let i0 = core::ptr::read_volatile(p.add(2)) as u64;
        if nblocks == 2 {
            let e1 = core::ptr::read_volatile(p.add(3)) as u64;
            let p1 = core::ptr::read_volatile(p.add(4)) as u64;
            let i1 = core::ptr::read_volatile(p.add(5)) as u64;
            (e0 | (e1 << 32), p0 | (p1 << 32), i0 | (i1 << 32))
        } else {
            (e0, p0, i0)
        }
    };
    let old_perm = cur.creds.cap_permitted.load(Ordering::Acquire);
    let old_inh = cur.creds.cap_inheritable.load(Ordering::Acquire);
    let bounding = cur.creds.cap_bounding.load(Ordering::Acquire);
    if new_perm & !old_perm != 0 {
        return -(Errno::Eperm.as_i32() as i64);
    }
    if new_eff & !new_perm != 0 {
        return -(Errno::Eperm.as_i32() as i64);
    }
    if new_inh & !((old_inh | old_perm) & bounding) != 0 {
        return -(Errno::Eperm.as_i32() as i64);
    }
    cur.creds.cap_permitted.store(new_perm, Ordering::Release);
    cur.creds.cap_effective.store(new_eff, Ordering::Release);
    cur.creds.cap_inheritable.store(new_inh, Ordering::Release);
    cur.creds.cap_ambient.fetch_and(new_perm & new_inh, Ordering::AcqRel);
    0
}
