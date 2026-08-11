// `capget(2)` / `capset(2)` marshalling shell: read the
// `__user_cap_header_struct`, resolve the target task, hand the numbers to
// `cap_policy`, write the `__user_cap_data_struct` blocks back. Every
// admission decision lives in `cap_policy` so hosted tests can drive it.

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::cap_policy::{cap_data_blocks, capget_early, capset_check, CapgetEarly, CapsetOld, CAPV3};

/// `sizeof(struct __user_cap_data_struct)` — effective, permitted, inheritable.
const CAP_DATA_BYTES: usize = 12;
/// `struct __user_cap_header_struct` member offsets.
const CAP_HDR_PID_OFF: u64 = 4;

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }

/// Linux `cap_validate_magic`: read the header version, and on an unknown one
/// write the kernel's preferred version back before reporting EINVAL. A
/// write-back that itself faults is EFAULT, and that errno reaches the caller
/// in place of the EINVAL — including a NULL-`dataptr` version probe.
///
/// Both copies go through `uaccess`, whose hand-written loops carry the
/// exception-table fixups; a range check alone would leave an unmapped user
/// header faulting the kernel.
fn cap_validate_magic(hp: u64) -> Result<usize, Errno> {
    let mut ver = [0u8; 4];
    uaccess::copy_from_user(&mut ver, hp)?;
    match cap_data_blocks(u32::from_ne_bytes(ver)) {
        Some(n) => Ok(n),
        None => {
            // libcap reads the magic, sees a mismatch, retries with V3.
            uaccess::copy_to_user(hp, &CAPV3.to_ne_bytes())?;
            Err(Errno::Einval)
        }
    }
}

/// `get_user(pid, &header->pid)`, which Linux issues only after the magic has
/// validated and (for capget) after the NULL-`dataptr` probe has returned.
fn read_cap_pid(hp: u64) -> Result<i32, Errno> {
    let mut pid = [0u8; 4];
    uaccess::copy_from_user(&mut pid, hp.saturating_add(CAP_HDR_PID_OFF))?;
    Ok(i32::from_ne_bytes(pid))
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

/// Encode `tocopy` `__user_cap_data_struct` blocks: `{u32 effective, u32
/// permitted, u32 inheritable}` per block, low half first, high half second.
/// # C: O(1)
fn encode_cap_data(eff: u64, perm: u64, inh: u64, nblocks: usize) -> ([u8; 2 * CAP_DATA_BYTES], usize) {
    let mut out = [0u8; 2 * CAP_DATA_BYTES];
    let words: [u32; 6] = [eff as u32, perm as u32, inh as u32,
                           (eff >> 32) as u32, (perm >> 32) as u32, (inh >> 32) as u32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    (out, nblocks * CAP_DATA_BYTES)
}

/// Decode the same blocks back into the raw triple `capset` admits. A v1
/// request carries one block, so the upper 32 bits stay zero — Linux's
/// documented fail-safe ("we silently drop the upper capabilities here")
/// rather than `-ERANGE`.
/// # C: O(1)
fn decode_cap_data(raw: &[u8], nblocks: usize) -> (u64, u64, u64) {
    let w = |i: usize| -> u64 {
        u32::from_ne_bytes([raw[i * 4], raw[i * 4 + 1], raw[i * 4 + 2], raw[i * 4 + 3]]) as u64
    };
    if nblocks == 2 { (w(0) | (w(3) << 32), w(1) | (w(4) << 32), w(2) | (w(5) << 32)) }
    else            { (w(0), w(1), w(2)) }
}

/// `capget`'s marshalling, with the target lookup as a parameter so a hosted
/// test can drive the whole user-memory path without a live task registry.
/// # C: O(1)
pub(super) fn capget_marshal(args: &SyscallArgs, load: impl FnOnce(i32) -> Result<(u64, u64, u64), i64>) -> i64 {
    let (hp, dp) = (args.a0, args.a1);
    let nblocks = match capget_early(cap_validate_magic(hp), dp) {
        CapgetEarly::Fail(rv) => return rv,
        CapgetEarly::Ok => return 0,
        CapgetEarly::Proceed(n) => n,
    };
    let pid = match read_cap_pid(hp) { Ok(v) => v, Err(_) => return efault() };
    let (eff, perm, inh) = match load(pid) { Ok(t) => t, Err(rv) => return rv };
    let (buf, len) = encode_cap_data(eff, perm, inh, nblocks);
    if uaccess::copy_to_user(dp, &buf[..len]).is_err() { return efault(); }
    0
}

/// `sys_capget(hdrp, datap)` — slot 125. Reads the version+pid from the
/// header, looks up the target task, and writes effective/permitted/
/// inheritable as N×{u32 effective, u32 permitted, u32 inheritable} blocks
/// (low32 of each u64 first, high32 second for v2/v3).
///
/// A NULL `datap` is a version probe and returns 0 even when the magic was
/// wrong — see `cap_policy::capget_early` for Linux's exact ladder. Note
/// capset has NO such case: `cap_validate_magic` failing there is reported
/// unconditionally.
/// # C: O(1)
pub(super) fn sys_capget(args: &SyscallArgs) -> i64 {
    capget_marshal(args, cap_load_target)
}

/// `capset`'s marshalling against an explicit calling task, so a hosted test
/// can drive it without `current()`.
/// # C: O(1)
pub(super) fn capset_on(cur: &crate::Task, args: &SyscallArgs) -> i64 {
    let (hp, dp) = (args.a0, args.a1);
    let nblocks = match cap_validate_magic(hp) {
        Ok(n) => n,
        Err(e) => return -(e.as_i32() as i64),
    };
    let pid = match read_cap_pid(hp) { Ok(v) => v, Err(_) => return efault() };
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
    let mut raw = [0u8; 2 * CAP_DATA_BYTES];
    let len = nblocks * CAP_DATA_BYTES;
    if uaccess::copy_from_user(&mut raw[..len], dp).is_err() { return efault(); }
    let (raw_eff, raw_perm, raw_inh) = decode_cap_data(&raw, nblocks);
    let old = CapsetOld {
        effective:   cur.creds.cap_effective.load(Ordering::Acquire),
        permitted:   cur.creds.cap_permitted.load(Ordering::Acquire),
        inheritable: cur.creds.cap_inheritable.load(Ordering::Acquire),
        bounding:    cur.creds.cap_bounding.load(Ordering::Acquire),
        ambient:     cur.creds.cap_ambient.load(Ordering::Acquire),
    };
    let new = match capset_check(old, raw_eff, raw_perm, raw_inh) {
        Ok(n) => n,
        Err(e) => return -(e.as_i32() as i64),
    };
    cur.creds.cap_permitted.store(new.permitted, Ordering::Release);
    cur.creds.cap_effective.store(new.effective, Ordering::Release);
    cur.creds.cap_inheritable.store(new.inheritable, Ordering::Release);
    cur.creds.cap_ambient.store(new.ambient, Ordering::Release);
    0
}

/// `sys_capset(hdrp, datap)` — slot 126. Linux only allows capset against
/// the calling task (pid==0 or pid==`task_pid_vnr(current)`); the admission
/// rules themselves are `cap_policy::capset_check`.
/// # C: O(1)
pub(super) fn sys_capset(args: &SyscallArgs) -> i64 {
    match crate::live::current() {
        Some(c) => capset_on(c, args),
        None => -(Errno::Esrch.as_i32() as i64),
    }
}
