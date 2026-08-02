// Linux keyrings — `add_key(2)` / `request_key(2)` / `keyctl(2)` over a real
// per-task keyring hierarchy. Each task resolves the special keyring ids
// (`@t/@p/@s/@u/@us`) to actual keyring objects; keys and keyrings share one
// serial space; a keyring is a Key of type "keyring" whose `members` holds the
// linked child serials.
//
// Module manifest:
// - uapi:    Linux keyctl/key constants — command codes, special ids, perm
//            bit layout, capability bytes, size limits. Numbers only.
// - types:   the registered `key_type` table — each type's read/update
//            methods, its `preparse` payload contract and quota charge, its
//            `vet_description` rule, and the `KEY_PERM_UNDEF` default-perm
//            computation.
// - store:   `struct key` state, the serial space, the special-keyring maps,
//            the per-uid `key_user` quota, the gc, and the raw
//            mint/resolve/link primitives.
// - perm:    `key_task_permission` + `key_validate` — THE choke-point every op
//            passes through. No op reads `perm`/`uid`/`gid`/`revoked` directly.
// - ops:     the per-op cores (rings / keys / links), each taking an explicit
//            `Ctx` so hosted tests drive them for arbitrary callers.
// - keyctl:  `keyctl(2)` command dispatch and its user-memory marshalling.
// - notify:  the ONE place a key event becomes a notification record for the
//            queues watching that key.
// - lifecycle: the fork / exec / exit / fsid-change transitions that move this
//            state in Linux because it lives in `cred`.
// - report:  `/proc/keys` and `/proc/key-users` rendering.
// - procfs:  the boot binding that hands those renderers, and the
//            `/proc/sys/kernel/keys/` values, to the procfs leaf crate.
//
// This file owns only the syscall entry points, the user-memory helpers they
// share, and the one place `sched::current()` is turned into a `Ctx`.
//
// Model vs Linux: Linux hangs every one of these on `cred`. Here the session,
// thread and `jit_keyring` state is keyed per-TID, the process keyring per-TGID
// and the user + user-session keyrings per-UID, which reproduces the cred
// sharing rules structurally — a `CLONE_THREAD` child shares its parent's tgid
// and therefore its process keyring, a fork does not — with `lifecycle`
// applying the transitions `copy_creds`/`prepare_exec_creds`/`put_cred` apply.

use alloc::string::String;
use alloc::vec::Vec;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

mod auth;
mod construct;
mod keyctl;
mod lifecycle;
mod notify;
mod ops;
mod perm;
mod procfs;
mod report;
mod store;
mod trace;
mod types;
// The complete `uapi/linux/keyctl.h` + `include/linux/key.h` number space:
// KEY_SPEC_* special ids, KEYCTL_* opcodes, KEY_REQKEY_DEFL_* defaults,
// KEY_NEED_*/KEY_{POS,USR,GRP,OTH}_* permission bits and the
// KEYCTL_CAPABILITIES byte-0/1 feature bits. Entries with no reader are the
// point: the unreached KEY_SPEC_/KEY_REQKEY_DEFL_ ids are rejected by range
// check rather than by name. Dropping them would make the table a subset
// (`docs/02`). The capability bits are NOT among them — each is read by the
// module that implements the feature and reported from there, so a bit and the
// behaviour behind it cannot disagree.
#[allow(dead_code, reason = "complete Linux keyctl UAPI number space; unreferenced entries are deliberate — see comment above")]
mod uapi;

pub use keyctl::sys_keyctl;
pub use procfs::register_procfs_hooks;
pub use lifecycle::{exec as exec_keys, exit as exit_keys, fork as fork_keys, fsids_changed};
pub use store::{persistent_expiry, quota_limit, set_persistent_expiry, set_quota_limit,
    QuotaKnob, TaskIds};
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

/// `add_key`/`request_key` description read. A NULL pointer is NOT a fault
/// here: the description is optional at the ABI, and an absent (or empty) one
/// leaves the type to generate one — which none of the registered types does,
/// so the create path answers EINVAL. Returning EFAULT instead would report a
/// bad pointer for an argument that was legitimately omitted.
fn read_user_key_desc_optional(p: u64) -> Result<String, i64> {
    if p == 0 { return Ok(String::new()); }
    read_user_key_desc(p)
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

/// `import_iovec` for `KEYCTL_INSTANTIATE_IOV`: gather `n` Linux `struct
/// iovec` segments into one payload. The segments are validated as a whole
/// BEFORE any is copied, so a bad pointer in the last one does not leave a
/// half-gathered payload to be instantiated. The combined length is bounded by
/// the same 1 MiB ceiling `KEYCTL_INSTANTIATE` applies — a vectored call must
/// not be a way around it. # C: O(n + total)
fn read_user_iov(p: u64, n: u64) -> Result<Vec<u8>, i64> {
    /// `sizeof(struct iovec)` — `void *iov_base; size_t iov_len;`.
    const IOVEC_SIZE: u64 = 16;
    const IOVEC_LEN_OFFSET: u64 = 8;
    if n == 0 { return Ok(Vec::new()); }
    let array_bytes = n.checked_mul(IOVEC_SIZE).ok_or(err(Errno::Efault))?;
    validate_user_buf(p, array_bytes, 8)?;
    let mut segs: Vec<(u64, u64)> = Vec::new();
    let mut total: u64 = 0;
    for i in 0..n {
        let e = p + i * IOVEC_SIZE;
        // SAFETY: the whole iovec array was validated above; e and e+8 lie inside it and the Linux ABI aligns both to 8.
        let base = unsafe { core::ptr::read_volatile(e as *const u64) };
        // SAFETY: same validated array range; iov_len sits at offset +8, 8-byte aligned.
        let len = unsafe { core::ptr::read_volatile((e + IOVEC_LEN_OFFSET) as *const u64) };
        if len == 0 { continue; }
        total = total.checked_add(len).ok_or(err(Errno::Einval))?;
        if total > KEY_MAX_PAYLOAD { return Err(err(Errno::Einval)); }
        validate_user_buf(base, len, 1)?;
        segs.push((base, len));
    }
    let mut out = Vec::with_capacity(total as usize);
    for (base, len) in segs {
        for i in 0..len {
            // SAFETY: every segment was validated readable above and none has been unmapped since — the caller holds no lock that would let it.
            out.push(unsafe { core::ptr::read_unaligned((base + i) as *const u8) });
        }
    }
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
            Ctx::with_caps(t, now_ns, c.has_cap(sched::cap::SYS_ADMIN), c.has_cap(sched::cap::SETUID))
        }
        None => Ctx::with_caps(TaskIds::default(), now_ns, true, true),
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

/// `sys_add_key(type, desc, payload, plen, keyring)` — slot 248, in the order
/// the syscall applies its checks:
///   1. `plen > 1024*1024-1` is EINVAL BEFORE anything is copied, so an absurd
///      length is rejected rather than attempted;
///   2. the type name is read (empty EINVAL, `.`-prefixed EPERM);
///   3. the description is read — a NULL or empty one is not a fault, it just
///      leaves the create path to answer EINVAL — and a `.`-prefixed
///      description for the `keyring` type is EPERM here, ahead of the payload
///      copy, so a bad payload pointer cannot mask it;
///   4. the payload is copied (EFAULT).
/// # C: O(N)
pub fn sys_add_key(args: &SyscallArgs) -> i64 {
    if args.a3 > KEY_MAX_PAYLOAD { return err(Errno::Einval); }
    let key_type = match read_user_key_type(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let description = match read_user_key_desc_optional(args.a1) { Ok(s) => s, Err(rv) => return rv };
    if types::dot_reserved(&key_type, &description) { return err(Errno::Eperm); }
    let payload = match read_user_bytes(args.a2, args.a3) { Ok(v) => v, Err(rv) => return rv };
    ops::add_key_core(&cur_ctx(), &key_type, &description, payload, args.a2 != 0, args.a4 as i32)
}

/// `sys_request_key(type, desc, callout, dest)` — slot 249.
///
/// The callout pointer being NULL is the whole difference between "does this
/// key exist" and "build it if it does not": a NULL callout means a miss is
/// ENOKEY and nothing is constructed, while ANY callout string — including the
/// empty one — makes a miss run `/sbin/request-key`. So the pointer is read
/// with `strndup_user(_callout_info, PAGE_SIZE)` semantics and its presence,
/// not its content, selects the path. # C: O(N)
pub fn sys_request_key(args: &SyscallArgs) -> i64 {
    let key_type = match read_user_key_type(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let description = match read_user_key_desc(args.a1) { Ok(s) => s, Err(rv) => return rv };
    let callout = if args.a2 == 0 { None } else {
        match read_user_key_cstr(args.a2, KEY_CALLOUT_MAX) { Ok(b) => Some(b), Err(rv) => return rv }
    };
    ops::request_key_core(&cur_ctx(), &key_type, &description, callout.as_deref(), args.a3 as i32)
}

/// `/proc/keys` as the CURRENT reader sees it — keys it may not VIEW are
/// omitted, so the file is a per-task view rather than a global dump. # C: O(N)
pub fn proc_keys() -> String {
    let c = cur_ctx();
    report::proc_keys(&c.t, c.now_ns)
}

/// `/proc/key-users` — the per-uid quota table. # C: O(N)
pub fn proc_key_users() -> String { report::proc_key_users() }

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
