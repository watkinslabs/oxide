// Real POSIX credentials syscalls per `13§5` and docs/14 cred-ABI.
//
// Single-arm dispatch helper for `syscall_glue.rs` to keep that file
// under the 1000-line cap (08§7).
// Replaces the previous "always-root, silent-0 setters" stubs with
// real ruid/euid/suid + rgid/egid/sgid storage on Task.creds.
//
// Permission model (Linux semantics):
//   * If euid == 0 (root), any transition is allowed.
//   * Otherwise, each non-(-1) target uid must already appear in
//     {ruid, euid, suid}. Same for gid triples.
//   * setuid(uid) by root sets ruid=euid=suid=fsuid=uid (all four).
//   * setuid(uid) by non-root sets euid=fsuid=uid only (ruid/suid
//     unchanged) — preserves the saved-uid hop-back hatch.
//   * setresuid(r,e,s) — `-1` (i.e. u32::MAX) means "no change" per
//     Linux; same for setresgid / setreuid / setregid.
//   * setfsuid/setfsgid return the previous fsuid/fsgid; never fail.


mod caps;

use caps::{sys_capget, sys_capset};
use syscall::SyscallArgs;
use syscall::errno::Errno;
use core::sync::atomic::Ordering;

/// `sys_getuid` — slot 102. Returns the real uid.
/// # C: O(1)
pub fn sys_getuid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => t.creds.ruid.load(Ordering::Acquire) as i64,
        None    => 0,
    }
}

/// `sys_geteuid` — slot 107. Returns the effective uid.
/// # C: O(1)
pub fn sys_geteuid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => t.creds.euid.load(Ordering::Acquire) as i64,
        None    => 0,
    }
}

/// `sys_getgid` — slot 104. Returns the real gid.
/// # C: O(1)
pub fn sys_getgid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => t.creds.rgid.load(Ordering::Acquire) as i64,
        None    => 0,
    }
}

/// `sys_getegid` — slot 108. Returns the effective gid.
/// # C: O(1)
pub fn sys_getegid(_args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(t) => t.creds.egid.load(Ordering::Acquire) as i64,
        None    => 0,
    }
}

/// Helper: write 3 u32s to user pointers (each may be NULL → skipped).
/// Returns Err(-EFAULT) if any non-NULL pointer falls outside USER_VA_END.
fn writeback3(p_a: u64, va: u32, p_b: u64, vb: u32, p_c: u64, vc: u32) -> Result<(), i64> {
    for &(p, v) in &[(p_a, va), (p_b, vb), (p_c, vc)] {
        if p == 0 { continue; }
        if p >= hal::USER_VA_END { return Err(-(Errno::Efault.as_i32() as i64)); }
        // SAFETY: p validated < USER_VA_END; CPL=0 writes through caller's AS; u32-aligned write to user memory at the syscall ABI's specified pointer.
        unsafe { core::ptr::write_volatile(p as *mut u32, v); }
    }
    Ok(())
}

/// `sys_getresuid(ruid_out, euid_out, suid_out)` — slot 118.
/// # C: O(1)
pub fn sys_getresuid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let r = cur.creds.ruid.load(Ordering::Acquire);
    let e = cur.creds.euid.load(Ordering::Acquire);
    let s = cur.creds.suid.load(Ordering::Acquire);
    match writeback3(args.a0, r, args.a1, e, args.a2, s) {
        Ok(()) => 0, Err(rv) => rv,
    }
}

/// `sys_getresgid(rgid_out, egid_out, sgid_out)` — slot 120.
/// # C: O(1)
pub fn sys_getresgid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let r = cur.creds.rgid.load(Ordering::Acquire);
    let e = cur.creds.egid.load(Ordering::Acquire);
    let s = cur.creds.sgid.load(Ordering::Acquire);
    match writeback3(args.a0, r, args.a1, e, args.a2, s) {
        Ok(()) => 0, Err(rv) => rv,
    }
}

const NOCHANGE: u32 = u32::MAX;

/// Linux `cap_emulate_setxuid` (security/commoncap.c). Called after
/// any setuid-family transition. Mirrors the kernel's POSIX-cap
/// emulation rules so a privileged daemon that drops uid actually
/// loses its caps — without this, openssh's `permanently_set_uid`
/// safety probe (setuid(0) after setresuid(uid,uid,uid)) succeeds,
/// the daemon aborts with `was able to restore old [e]uid`, and the
/// user session never starts. Rules per Linux:
///   * If any of {old_ruid, old_euid, old_suid} was 0 AND none of
///     {new_ruid, new_euid, new_suid} is 0 → clear permitted +
///     effective (caps are gone permanently for this task).
///   * Else if old_euid == 0 and new_euid != 0 → clear effective
///     (caps preserved in permitted, can be re-raised via capset).
///   * Else if old_euid != 0 and new_euid == 0 → restore effective
///     from permitted.
/// The fsuid transitions mirror this for the file-related caps
/// (CHOWN/DAC_OVERRIDE/DAC_READ_SEARCH/FOWNER/FSETID/MKNOD/LINUX_IMMUTABLE).
fn cap_emulate_setxuid(
    cur: &crate::Task,
    old_r: u32, old_e: u32, old_s: u32,
    new_r: u32, new_e: u32, new_s: u32,
    old_fs: u32, new_fs: u32,
) {
    let had_root = old_r == 0 || old_e == 0 || old_s == 0;
    let has_root = new_r == 0 || new_e == 0 || new_s == 0;
    // Linux (security/commoncap.c): the full permitted+effective clear on a
    // root→non-root id transition is SUPPRESSED when SECURE_KEEP_CAPS
    // (PR_SET_KEEPCAPS/SECBIT_KEEP_CAPS) is set. Privilege-dropping daemons — systemd-networkd,
    // sshd — set PR_SET_KEEPCAPS, drop the uid, then re-raise their effective
    // set from the retained permitted via capset. Without honouring it,
    // permitted was wiped and the daemon's capset("acquire CAP_SETPCAP")
    // failed with EPERM ("Failed to drop privileges").
    if had_root && !has_root && !cur.creds.keeps_caps() {
        cur.creds.cap_permitted.store(0, Ordering::Release);
        cur.creds.cap_effective.store(0, Ordering::Release);
        cur.creds.cap_ambient.store(0, Ordering::Release);
    } else if old_e == 0 && new_e != 0 {
        cur.creds.cap_effective.store(0, Ordering::Release);
    } else if old_e != 0 && new_e == 0 {
        let perm = cur.creds.cap_permitted.load(Ordering::Acquire);
        cur.creds.cap_effective.store(perm, Ordering::Release);
    }
    if old_e != new_e {
        cur.creds.cap_ambient.store(0, Ordering::Release);
    }
    const FS_CAP_MASK: u64 = (1u64 << crate::cap::CHOWN)
        | (1u64 << crate::cap::DAC_OVERRIDE)
        | (1u64 << crate::cap::DAC_READ_SEARCH)
        | (1u64 << crate::cap::FOWNER)
        | (1u64 << crate::cap::FSETID)
        | (1u64 << crate::cap::MKNOD)
        | (1u64 << crate::cap::LINUX_IMMUTABLE);
    if old_fs == 0 && new_fs != 0 {
        let e = cur.creds.cap_effective.load(Ordering::Acquire);
        cur.creds.cap_effective.store(e & !FS_CAP_MASK, Ordering::Release);
    } else if old_fs != 0 && new_fs == 0 {
        let perm = cur.creds.cap_permitted.load(Ordering::Acquire);
        let e = cur.creds.cap_effective.load(Ordering::Acquire);
        cur.creds.cap_effective.store(e | (perm & FS_CAP_MASK), Ordering::Release);
    }
}

/// True if `target` is acceptable for a non-root uid transition —
/// i.e. it appears in the existing {ruid, euid, suid} triple.
fn uid_allowed(target: u32, r: u32, e: u32, s: u32) -> bool {
    target == r || target == e || target == s
}

/// `sys_setresuid(ruid, euid, suid)` — slot 117.
/// Free-transition allowed when the task holds CAP_SETUID (F92).
/// Without the cap, transitions are confined to the existing triple.
/// # C: O(1)
pub fn sys_setresuid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let r = args.a0 as u32;
    let e = args.a1 as u32;
    let s = args.a2 as u32;
    let cr = cur.creds.ruid.load(Ordering::Acquire);
    let ce = cur.creds.euid.load(Ordering::Acquire);
    let cs = cur.creds.suid.load(Ordering::Acquire);
    if !cur.has_cap(crate::cap::SETUID) {
        if r != NOCHANGE && !uid_allowed(r, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
        if e != NOCHANGE && !uid_allowed(e, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
        if s != NOCHANGE && !uid_allowed(s, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
    }
    let old_fs = cur.creds.fsuid.load(Ordering::Acquire);
    let new_r = if r != NOCHANGE { r } else { cr };
    let new_e = if e != NOCHANGE { e } else { ce };
    let new_s = if s != NOCHANGE { s } else { cs };
    let new_fs = if e != NOCHANGE { e } else { old_fs };
    if r != NOCHANGE { cur.creds.ruid.store(r, Ordering::Release); }
    if e != NOCHANGE {
        cur.creds.euid.store(e, Ordering::Release);
        cur.creds.fsuid.store(e, Ordering::Release); // Linux mirrors euid into fsuid
    }
    if s != NOCHANGE { cur.creds.suid.store(s, Ordering::Release); }
    cap_emulate_setxuid(&cur, cr, ce, cs, new_r, new_e, new_s, old_fs, new_fs);
    0
}

/// `sys_setresgid(rgid, egid, sgid)` — slot 119. Cap = SETGID.
/// # C: O(1)
pub fn sys_setresgid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let r = args.a0 as u32;
    let e = args.a1 as u32;
    let s = args.a2 as u32;
    let cr = cur.creds.rgid.load(Ordering::Acquire);
    let ce = cur.creds.egid.load(Ordering::Acquire);
    let cs = cur.creds.sgid.load(Ordering::Acquire);
    if !cur.has_cap(crate::cap::SETGID) {
        if r != NOCHANGE && !uid_allowed(r, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
        if e != NOCHANGE && !uid_allowed(e, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
        if s != NOCHANGE && !uid_allowed(s, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
    }
    if r != NOCHANGE { cur.creds.rgid.store(r, Ordering::Release); }
    if e != NOCHANGE {
        cur.creds.egid.store(e, Ordering::Release);
        cur.creds.fsgid.store(e, Ordering::Release);
    }
    if s != NOCHANGE { cur.creds.sgid.store(s, Ordering::Release); }
    0
}

/// `sys_setuid(uid)` — slot 105.
/// # C: O(1)
pub fn sys_setuid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let uid = args.a0 as u32;
    let cr = cur.creds.ruid.load(Ordering::Acquire);
    let ce = cur.creds.euid.load(Ordering::Acquire);
    let cs = cur.creds.suid.load(Ordering::Acquire);
    let old_fs = cur.creds.fsuid.load(Ordering::Acquire);
    if cur.has_cap(crate::cap::SETUID) {
        cur.creds.ruid.store(uid,  Ordering::Release);
        cur.creds.euid.store(uid,  Ordering::Release);
        cur.creds.suid.store(uid,  Ordering::Release);
        cur.creds.fsuid.store(uid, Ordering::Release);
        cap_emulate_setxuid(&cur, cr, ce, cs, uid, uid, uid, old_fs, uid);
        return 0;
    }
    if !uid_allowed(uid, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
    cur.creds.euid.store(uid,  Ordering::Release);
    cur.creds.fsuid.store(uid, Ordering::Release);
    cap_emulate_setxuid(&cur, cr, ce, cs, cr, uid, cs, old_fs, uid);
    0
}

/// `sys_setgid(gid)` — slot 106.
/// # C: O(1)
pub fn sys_setgid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let gid = args.a0 as u32;
    if cur.has_cap(crate::cap::SETGID) {
        cur.creds.rgid.store(gid,  Ordering::Release);
        cur.creds.egid.store(gid,  Ordering::Release);
        cur.creds.sgid.store(gid,  Ordering::Release);
        cur.creds.fsgid.store(gid, Ordering::Release);
        return 0;
    }
    let cr = cur.creds.rgid.load(Ordering::Acquire);
    let ce = cur.creds.egid.load(Ordering::Acquire);
    let cs = cur.creds.sgid.load(Ordering::Acquire);
    if !uid_allowed(gid, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
    cur.creds.egid.store(gid,  Ordering::Release);
    cur.creds.fsgid.store(gid, Ordering::Release);
    0
}

/// `sys_setreuid(ruid, euid)` — slot 113.
/// Linux: -1 preserves; non-root may swap r/e but only between
/// existing {ruid, euid, suid}. If euid is changed and ruid was
/// either set explicitly or != euid, suid follows the new euid.
/// # C: O(1)
pub fn sys_setreuid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let r = args.a0 as u32;
    let e = args.a1 as u32;
    let cr = cur.creds.ruid.load(Ordering::Acquire);
    let ce = cur.creds.euid.load(Ordering::Acquire);
    let cs = cur.creds.suid.load(Ordering::Acquire);
    if !cur.has_cap(crate::cap::SETUID) {
        if r != NOCHANGE && !uid_allowed(r, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
        if e != NOCHANGE && !uid_allowed(e, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
    }
    let old_fs = cur.creds.fsuid.load(Ordering::Acquire);
    let new_r = if r != NOCHANGE { r } else { cr };
    let new_e = if e != NOCHANGE { e } else { ce };
    cur.creds.ruid.store(new_r, Ordering::Release);
    cur.creds.euid.store(new_e, Ordering::Release);
    cur.creds.fsuid.store(new_e, Ordering::Release);
    // suid follows new euid when r was set explicitly OR new_e differs from old ruid
    let new_s = if r != NOCHANGE || new_e != cr { new_e } else { cs };
    if r != NOCHANGE || new_e != cr {
        cur.creds.suid.store(new_e, Ordering::Release);
    }
    cap_emulate_setxuid(&cur, cr, ce, cs, new_r, new_e, new_s, old_fs, new_e);
    0
}

/// `sys_setregid(rgid, egid)` — slot 114.
/// # C: O(1)
pub fn sys_setregid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let r = args.a0 as u32;
    let e = args.a1 as u32;
    let cr = cur.creds.rgid.load(Ordering::Acquire);
    let ce = cur.creds.egid.load(Ordering::Acquire);
    let cs = cur.creds.sgid.load(Ordering::Acquire);
    if !cur.has_cap(crate::cap::SETGID) {
        if r != NOCHANGE && !uid_allowed(r, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
        if e != NOCHANGE && !uid_allowed(e, cr, ce, cs) { return -(Errno::Eperm.as_i32() as i64); }
    }
    let new_r = if r != NOCHANGE { r } else { cr };
    let new_e = if e != NOCHANGE { e } else { ce };
    cur.creds.rgid.store(new_r, Ordering::Release);
    cur.creds.egid.store(new_e, Ordering::Release);
    cur.creds.fsgid.store(new_e, Ordering::Release);
    if r != NOCHANGE || new_e != cr {
        cur.creds.sgid.store(new_e, Ordering::Release);
    }
    0
}

/// `sys_setfsuid(uid)` — slot 122. Returns previous fsuid; never
/// fails per Linux. Permission: root, or new fsuid in
/// {ruid, euid, suid, current fsuid}; otherwise change is silently
/// dropped and the previous value still returned.
/// # C: O(1)
pub fn sys_setfsuid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let uid = args.a0 as u32;
    let prev = cur.creds.fsuid.load(Ordering::Acquire);
    if uid == NOCHANGE { return prev as i64; }
    let cr = cur.creds.ruid.load(Ordering::Acquire);
    let ce = cur.creds.euid.load(Ordering::Acquire);
    let cs = cur.creds.suid.load(Ordering::Acquire);
    if cur.has_cap(crate::cap::SETUID) || uid == prev || uid_allowed(uid, cr, ce, cs) {
        cur.creds.fsuid.store(uid, Ordering::Release);
    }
    prev as i64
}

/// `sys_setfsgid(gid)` — slot 123. Same semantics as setfsuid for the
/// gid triple.
/// # C: O(1)
pub fn sys_setfsgid(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let gid = args.a0 as u32;
    let prev = cur.creds.fsgid.load(Ordering::Acquire);
    if gid == NOCHANGE { return prev as i64; }
    let cr = cur.creds.rgid.load(Ordering::Acquire);
    let ce = cur.creds.egid.load(Ordering::Acquire);
    let cs = cur.creds.sgid.load(Ordering::Acquire);
    if cur.has_cap(crate::cap::SETGID) || gid == prev || uid_allowed(gid, cr, ce, cs) {
        cur.creds.fsgid.store(gid, Ordering::Release);
    }
    prev as i64
}

/// `sys_getgroups(size, list)` — slot 115. Returns ngroups; if
/// size > 0 writes the supplementary group list to `list`. size==0
/// is a query (returns ngroups without writing).
/// # C: O(NGROUPS_V1)
pub fn sys_getgroups(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let size = args.a0 as usize;
    let list = args.a1;
    let n = cur.creds.ngroups.load(Ordering::Acquire) as usize;
    if size == 0 { return n as i64; }
    if size < n { return -(Errno::Einval.as_i32() as i64); }
    if list == 0 || list >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    if list.checked_add((n * 4) as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: range validated; CPL=0 writes through caller's AS; we hold the single-mutator invariant on cur (running task on this CPU).
    unsafe {
        let g = &*cur.creds.groups.get();
        let dst = list as *mut u32;
        for i in 0..n {
            core::ptr::write_volatile(dst.add(i), g[i]);
        }
    }
    n as i64
}

/// `sys_setgroups(size, list)` — slot 116. Replaces the supplementary
/// group list. Linux requires CAP_SETGID (root for v1).
/// # C: O(NGROUPS_V1)
pub fn sys_setgroups(args: &SyscallArgs) -> i64 {
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    if !cur.has_cap(crate::cap::SETGID) { return -(Errno::Eperm.as_i32() as i64); }
    let size = args.a0 as usize;
    let list = args.a1;
    if size > crate::Creds::NGROUPS_V1 { return -(Errno::Einval.as_i32() as i64); }
    if size == 0 {
        cur.creds.ngroups.store(0, Ordering::Release);
        return 0;
    }
    if list == 0 || list >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    if list.checked_add((size * 4) as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: range validated; CPL=0 reads through caller's AS; single-mutator invariant on cur.
    unsafe {
        let src = list as *const u32;
        let g = &mut *cur.creds.groups.get();
        for i in 0..size {
            g[i] = core::ptr::read_volatile(src.add(i));
        }
        cur.creds.ngroups.store(size as u32, Ordering::Release);
    }
    0
}

/// Dispatch every cred-family syscall (`getuid`/`setuid`/etc.) from
/// a single match arm in `syscall_glue.rs`. Returns `None` if `nr`
/// is not a cred slot so the caller can fall through.
/// # C: O(1)
pub fn cred_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use syscall::nrs::*;
    let rv = match nr {
        NR_GETUID    => sys_getuid(args),
        NR_GETEUID   => sys_geteuid(args),
        NR_GETGID    => sys_getgid(args),
        NR_GETEGID   => sys_getegid(args),
        NR_GETRESUID => sys_getresuid(args),
        NR_GETRESGID => sys_getresgid(args),
        NR_SETUID    => sys_setuid(args),
        NR_SETGID    => sys_setgid(args),
        NR_SETREUID  => sys_setreuid(args),
        NR_SETREGID  => sys_setregid(args),
        NR_SETRESUID => sys_setresuid(args),
        NR_SETRESGID => sys_setresgid(args),
        NR_SETFSUID  => sys_setfsuid(args),
        NR_SETFSGID  => sys_setfsgid(args),
        NR_GETGROUPS => sys_getgroups(args),
        NR_SETGROUPS => sys_setgroups(args),
        NR_CAPGET    => sys_capget(args),
        NR_CAPSET    => sys_capset(args),
        _ => return None,
    };
    Some(rv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_task() -> crate::Task {
        crate::Task::new(1, "cred-test", crate::SchedClass::Normal { weight: 1024 })
    }

    #[test]
    fn secure_keep_caps_preserves_permitted_across_uid_drop() {
        let task = root_task();
        task.creds.securebits.store(crate::Creds::SECBIT_KEEP_CAPS, Ordering::Release);
        task.creds.cap_ambient.store(crate::Creds::CAP_FULL, Ordering::Release);

        cap_emulate_setxuid(&task, 0, 0, 0, 1000, 1000, 1000, 0, 1000);

        assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), crate::Creds::CAP_FULL);
        assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), 0);
        assert_eq!(task.creds.cap_ambient.load(Ordering::Acquire), 0);
    }

    #[test]
    fn uid_drop_without_keep_caps_clears_permitted() {
        let task = root_task();

        cap_emulate_setxuid(&task, 0, 0, 0, 1000, 1000, 1000, 0, 1000);

        assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), 0);
        assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), 0);
    }
}
