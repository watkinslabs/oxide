// Linux keyrings — `add_key(2)` / `request_key(2)` / `keyctl(2)` over a real
// per-task keyring hierarchy. Each task resolves the special keyring ids
// (`@t/@p/@s/@u/@us`) to actual keyring objects; keys and keyrings share one
// serial space; a keyring is a Key of type "keyring" whose `members` holds the
// linked child serials.
//
// Module manifest:
// - uapi:    Linux keyctl/key constants — command codes, special ids, perm
//            bit layout, capability bytes, size limits. Numbers only.
// - types:   the registered `key_type` table, its `vet_description` rules and
//            the `KEY_PERM_UNDEF` default-perm computation.
// - store:   `struct key` state, the serial space, the special-keyring maps,
//            and the raw mint/resolve/link primitives.
// - perm:    `key_task_permission` + `key_validate` — THE choke-point every op
//            passes through. No op reads `perm`/`uid`/`gid`/`revoked` directly.
// - ops:     the per-op cores (rings / keys / links), each taking an explicit
//            `Ctx` so hosted tests drive them for arbitrary callers.
// - keyctl:  `keyctl(2)` command dispatch and its user-memory marshalling.
//
// This file owns only the syscall entry points, the user-memory helpers they
// share, and the one place `sched::current()` is turned into a `Ctx`.
//
// Model vs Linux: session/thread keyrings are keyed per-TID, the process
// keyring per-TGID, the user + user-session keyrings per-UID; fork copies the
// parent's session serial via `inherit_session`. A login session sharing ONE
// session keyring across several processes is reached the way Linux reaches
// it — `KEYCTL_JOIN_SESSION_KEYRING` with a name, which pam_keyinit and
// systemd use.

use alloc::string::String;
use alloc::vec::Vec;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

mod keyctl;
mod ops;
mod perm;
mod store;
mod types;
// The complete `uapi/linux/keyctl.h` + `include/linux/key.h` number space:
// KEY_SPEC_* special ids, KEYCTL_* opcodes, KEY_REQKEY_DEFL_* defaults,
// KEY_NEED_*/KEY_{POS,USR,GRP,OTH}_* permission bits and the
// KEYCTL_CAPABILITIES byte-0/1 feature bits. Entries with no reader are the
// point: `KEYCTL_CAPS0_{DIFFIE_HELLMAN,PUBLIC_KEY,BIG_KEY}` and
// `KEYCTL_CAPS1_NOTIFICATIONS` name features this build reports as absent, and
// the unreached KEY_SPEC_/KEY_REQKEY_DEFL_ ids are rejected by range check
// rather than by name. Dropping them would make the table a subset (`docs/02`).
#[allow(dead_code, reason = "complete Linux keyctl UAPI number space; unreferenced entries are deliberate — see comment above")]
mod uapi;

pub use keyctl::sys_keyctl;
pub use ops::inherit_session;
pub use store::TaskIds;
use ops::Ctx;
use uapi::*;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn key_string_from_bytes(bytes: &[u8]) -> String {
    vfs::path_from_bytes(bytes)
}

fn read_user_key_cstr(p: u64, max: usize) -> Result<Vec<u8>, i64> {
    if p == 0 { return Err(err(Errno::Efault)); }
    match syscall::scan_user_cstr(p, max as u64, |va| {
        // SAFETY: scan_user_cstr validates each user VA before this byte read.
        unsafe { core::ptr::read_unaligned(va as *const u8) }
    }) {
        Ok(b) => Ok(b),
        Err(Errno::Enametoolong) => Err(err(Errno::Einval)),
        Err(e) => Err(err(e)),
    }
}

/// `key_get_type_from_user`: a bounded copy of the type name, rejecting an
/// empty name (EINVAL) and any name starting with `.` (EPERM — the dot prefix
/// is reserved for kernel-internal types such as `.request_key_auth`).
fn read_user_key_type(p: u64) -> Result<String, i64> {
    let b = read_user_key_cstr(p, KEY_TYPE_MAX)?;
    if b.is_empty() { return Err(err(Errno::Einval)); }
    if b[0] == b'.' { return Err(err(Errno::Eperm)); }
    Ok(key_string_from_bytes(&b))
}

fn read_user_key_desc(p: u64) -> Result<String, i64> {
    let b = read_user_key_cstr(p, KEY_MAX_DESC_SIZE)?;
    Ok(key_string_from_bytes(&b))
}

fn read_user_bytes(p: u64, len: u64) -> Result<Vec<u8>, i64> {
    if len == 0 { return Ok(Vec::new()); }
    if len > KEY_MAX_PAYLOAD { return Err(err(Errno::Einval)); }
    validate_user_buf(p, len, 1)?;
    let len = len as usize;
    let mut out = alloc::vec![0u8; len];
    // SAFETY: exact user byte range validated; destination is a kernel-owned Vec.
    unsafe { for i in 0..len { out[i] = core::ptr::read_unaligned((p + i as u64) as *const u8); } }
    Ok(out)
}

/// Raw copy-out of an exact byte range. # C: O(n)
fn write_user_bytes(p: u64, src: &[u8]) -> Result<(), i64> {
    if src.is_empty() { return Ok(()); }
    validate_user_buf_writable(p, src.len() as u64, 1)?;
    // SAFETY: exact user byte range validated writable; source is kernel-owned.
    unsafe { for i in 0..src.len() { core::ptr::write_unaligned((p + i as u64) as *mut u8, src[i]); } }
    Ok(())
}

/// `KEYCTL_READ` / `KEYCTL_GET_SECURITY` copy-out: write at most `buflen`
/// bytes and always return the FULL length, so a caller that guessed short
/// learns the real size and retries. A NULL buffer or zero length is a
/// length query (Linux `if (!buffer || !buflen)` → return the length only).
/// # C: O(n)
fn write_user_capped(buf_p: u64, buflen: u64, src: &[u8]) -> i64 {
    let full = src.len() as i64;
    if buf_p == 0 || buflen == 0 { return full; }
    let n = core::cmp::min(buflen as usize, src.len());
    match write_user_bytes(buf_p, &src[..n]) { Ok(()) => full, Err(rv) => rv }
}

/// `KEYCTL_DESCRIBE` copy-out: Linux copies ONLY when the caller's buffer can
/// take the whole descriptor (`if (buffer && buflen >= ret)`), and otherwise
/// returns the required length having written nothing — a half-written
/// descriptor would be parsed as a complete one. # C: O(n)
fn write_user_exact(buf_p: u64, buflen: u64, src: &[u8]) -> i64 {
    let full = src.len() as i64;
    if buf_p == 0 || buflen < src.len() as u64 { return full; }
    match write_user_bytes(buf_p, src) { Ok(()) => full, Err(rv) => rv }
}

/// The one place `sched::current()` becomes an op [`Ctx`]. Key ownership and
/// permission both key on the FILESYSTEM ids (`cred->fsuid`/`fsgid`), which is
/// what `key_alloc` and `key_task_permission` read. Falls back to uid/gid 0
/// with tid/tgid 0 pre-sched (boot). # C: O(groups)
fn cur_ctx() -> Ctx {
    use core::sync::atomic::Ordering::Acquire;
    let now_ns = monotonic_now_ns();
    match sched::current() {
        Some(c) => {
            let t = TaskIds {
                tid: c.tid,
                tgid: c.vtgid.load(Acquire),
                fsuid: c.creds.fsuid.load(Acquire),
                fsgid: c.creds.fsgid.load(Acquire),
                groups: c.creds.group_list().map(|g| g.to_vec()).unwrap_or_default(),
            };
            Ctx::new(t, now_ns, c.has_cap(sched::cap::SYS_ADMIN))
        }
        None => Ctx::new(TaskIds::default(), now_ns, true),
    }
}

/// The live parent-task facts `KEYCTL_SESSION_TO_PARENT` tests. `None` when
/// the caller has no parent task to hand its session keyring to.
/// # C: O(1)
fn parent_info() -> Option<ops::ParentInfo> {
    use core::sync::atomic::Ordering::Acquire;
    let p = sched::current()?.parent()?;
    Some(ops::ParentInfo {
        tid: p.tid,
        vpid: p.vtgid.load(Acquire),
        // SAFETY: `mm` is read-only here through a live Arc<Task>; the pointer is only tested for presence, never dereferenced or retained.
        has_mm: unsafe { (*p.mm.get()).is_some() },
        single_threaded: p.thread_group.is_single_member(),
        uid:  p.creds.ruid.load(Acquire),
        euid: p.creds.euid.load(Acquire),
        suid: p.creds.suid.load(Acquire),
        gid:  p.creds.rgid.load(Acquire),
        egid: p.creds.egid.load(Acquire),
        sgid: p.creds.sgid.load(Acquire),
    })
}

/// `sys_add_key(type, desc, payload, plen, keyring)` — slot 248. Linux checks
/// the payload length BEFORE it copies anything (`plen > 1024*1024-1` is
/// EINVAL), so an absurd length is rejected rather than attempted.
/// # C: O(N)
pub fn sys_add_key(args: &SyscallArgs) -> i64 {
    if args.a3 > KEY_MAX_PAYLOAD { return err(Errno::Einval); }
    let key_type = match read_user_key_type(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let description = match read_user_key_desc(args.a1) { Ok(s) => s, Err(rv) => return rv };
    let payload = match read_user_bytes(args.a2, args.a3) { Ok(v) => v, Err(rv) => return rv };
    ops::add_key_core(&cur_ctx(), &key_type, &description, payload, args.a4 as i32)
}

/// `sys_request_key(type, desc, callout, dest)` — slot 249. The callout string
/// is still validated (Linux `strndup_user(_callout_info, PAGE_SIZE)` faults
/// on a bad pointer before the search runs) even though no `/sbin/request-key`
/// helper exists to consume it. # C: O(N)
pub fn sys_request_key(args: &SyscallArgs) -> i64 {
    let key_type = match read_user_key_type(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let description = match read_user_key_desc(args.a1) { Ok(s) => s, Err(rv) => return rv };
    if args.a2 != 0 {
        if let Err(rv) = read_user_key_cstr(args.a2, KEY_CALLOUT_MAX) { return rv; }
    }
    ops::request_key_core(&cur_ctx(), &key_type, &description, args.a3 as i32)
}

/// Dispatch for the three keyring slots. # C: O(1)
pub fn keyring_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use syscall::nrs::*;
    let rv = match nr {
        NR_ADD_KEY     => sys_add_key(args),
        NR_REQUEST_KEY => sys_request_key(args),
        NR_KEYCTL      => sys_keyctl(args),
        _ => return None,
    };
    Some(rv)
}

/// Read the monotonic clock for `key_validate`'s expiry test and
/// `KEYCTL_SET_TIMEOUT`. Arch-gated so every `ops::*_core` stays cfg-free.
/// # C: O(1)
fn monotonic_now_ns() -> u64 {
    #[cfg(target_os = "oxide-kernel")]
    use hal::TimerOps;
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(target_os = "oxide-kernel"))] { 0u64 }
}

#[cfg(test)] mod tests;
