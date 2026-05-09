// Linux keyring (`add_key` / `request_key` / `keyctl`) — minimal real
// impl backed by a single global key store. Replaces the silent-0
// "synthetic key serial" lie that pretended PAM/sudo/dbus key probes
// succeeded without storing anything.
//
// v1 limitations (documented as ENOSYS / silent-0 only where honest):
//   * One global keyring instead of per-task session/process/user
//     hierarchies. KEYCTL_GET_KEYRING_ID returns a single sentinel
//     for any of the special @s/@u/@p/@t/@us/@g handles.
//   * No expiry sweeper — SET_TIMEOUT records the value but never
//     fires (most callers re-arm proactively).
//   * No DH/PKCS-11 key types; "user" / "logon" / "keyring" cover
//     PAM/login/sudo/sshd.
//   * No revocation propagation — REVOKE marks the slot revoked;
//     subsequent ops return EKEYREVOKED.
//
// Real per-task keyring trees + expiry sweep + DH key derivation ride
// a follow-up.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// Sentinel "global keyring" serial. All KEYCTL_GET_KEYRING_ID(@s/@u/@p)
/// requests fold to this value for v1.
pub const GLOBAL_KEYRING_SERIAL: i32 = 1;

#[derive(Default)]
pub struct Key {
    pub serial: i32,
    pub key_type: String,
    pub description: String,
    pub payload: Vec<u8>,
    pub perm: u32,
    pub uid: u32,
    pub gid: u32,
    pub expiry_ns: u64,
    pub revoked: bool,
}

#[derive(Default)]
struct Store {
    next_serial: i32,
    keys: BTreeMap<i32, Key>,
}

static STORE: Spinlock<Store, TaskListClass> = Spinlock::new(Store {
    next_serial: GLOBAL_KEYRING_SERIAL + 1,
    keys: BTreeMap::new(),
});

fn read_user_cstr_owned(p: u64, max: usize) -> Result<String, i64> {
    if p == 0 || p >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p validated < USER_VA_END; bounded read via existing helper.
    let bytes = unsafe { crate::devfs::read_user_cstr(p, max) };
    let s = bytes.and_then(|b| core::str::from_utf8(b).ok())
        .ok_or(-(Errno::Einval.as_i32() as i64))?;
    Ok(String::from(s))
}

fn read_user_bytes(p: u64, len: usize) -> Result<Vec<u8>, i64> {
    if len == 0 { return Ok(Vec::new()); }
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add(len as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let mut out = alloc::vec![0u8; len];
    // SAFETY: p+len validated < USER_VA_END; CPL=0 byte reads through caller's AS into kernel-owned buffer.
    unsafe {
        for i in 0..len {
            out[i] = core::ptr::read_volatile((p + i as u64) as *const u8);
        }
    }
    Ok(out)
}

/// `sys_add_key(type, description, payload, plen, keyring)` — slot 217.
/// Stores a new key, returns its serial.
/// # C: O(N_keys)
pub fn kernel_sys_add_key(args: &SyscallArgs) -> i64 {
    let type_p = args.a0;
    let desc_p = args.a1;
    let payload_p = args.a2;
    let plen   = args.a3 as usize;
    let _ring  = args.a4 as i32;
    let key_type = match read_user_cstr_owned(type_p, 64) { Ok(s) => s, Err(rv) => return rv };
    let description = match read_user_cstr_owned(desc_p, 256) { Ok(s) => s, Err(rv) => return rv };
    let payload = match read_user_bytes(payload_p, plen) { Ok(v) => v, Err(rv) => return rv };
    let mut g = STORE.lock();
    let serial = g.next_serial;
    g.next_serial = g.next_serial.wrapping_add(1);
    let cur = crate::sched::current();
    let (uid, gid) = match cur {
        Some(c) => (c.creds.euid.load(core::sync::atomic::Ordering::Acquire),
                    c.creds.egid.load(core::sync::atomic::Ordering::Acquire)),
        None    => (0, 0),
    };
    g.keys.insert(serial, Key {
        serial, key_type, description, payload,
        perm: 0x3f3f0000, uid, gid, expiry_ns: 0, revoked: false,
    });
    serial as i64
}

/// `sys_request_key(type, description, callout, dest_keyring)` — slot 218.
/// Searches the global key store by (type, description). v1 has no
/// callout helper, so missing keys return ENOKEY immediately.
/// # C: O(N_keys)
pub fn kernel_sys_request_key(args: &SyscallArgs) -> i64 {
    const ENOKEY: i32 = 126;
    let type_p = args.a0;
    let desc_p = args.a1;
    let key_type = match read_user_cstr_owned(type_p, 64) { Ok(s) => s, Err(rv) => return rv };
    let description = match read_user_cstr_owned(desc_p, 256) { Ok(s) => s, Err(rv) => return rv };
    let g = STORE.lock();
    for k in g.keys.values() {
        if k.revoked { continue; }
        if k.key_type == key_type && k.description == description {
            return k.serial as i64;
        }
    }
    -(ENOKEY as i64)
}

const KEYCTL_GET_KEYRING_ID:     u64 = 0;
const KEYCTL_JOIN_SESSION_KEYRING: u64 = 1;
const KEYCTL_UPDATE:             u64 = 2;
const KEYCTL_REVOKE:             u64 = 3;
const KEYCTL_DESCRIBE:           u64 = 6;
const KEYCTL_CLEAR:              u64 = 7;
const KEYCTL_SEARCH:             u64 = 10;
const KEYCTL_READ:               u64 = 11;
const KEYCTL_SET_TIMEOUT:        u64 = 15;
const KEYCTL_GET_PERSISTENT:     u64 = 22;
const KEYCTL_SET_REQKEY_KEYRING: u64 = 14;

/// Single dispatch helper for the three keyring slots.
/// # C: O(1)
pub fn keyring_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use crate::syscall_nrs::*;
    let rv = match nr {
        NR_ADD_KEY     => kernel_sys_add_key(args),
        NR_REQUEST_KEY => kernel_sys_request_key(args),
        NR_KEYCTL      => kernel_sys_keyctl(args),
        _ => return None,
    };
    Some(rv)
}

/// `sys_keyctl(op, arg2, arg3, arg4, arg5)` — slot 219.
/// # C: depends on op
pub fn kernel_sys_keyctl(args: &SyscallArgs) -> i64 {
    const EKEYREVOKED: i32 = 128;
    const ENOKEY:      i32 = 126;
    match args.a0 {
        KEYCTL_GET_KEYRING_ID | KEYCTL_JOIN_SESSION_KEYRING
        | KEYCTL_GET_PERSISTENT | KEYCTL_SET_REQKEY_KEYRING => GLOBAL_KEYRING_SERIAL as i64,
        KEYCTL_REVOKE => {
            let serial = args.a1 as i32;
            let mut g = STORE.lock();
            match g.keys.get_mut(&serial) {
                Some(k) => { k.revoked = true; 0 }
                None    => -(ENOKEY as i64),
            }
        }
        KEYCTL_CLEAR => {
            // Clear our global ring: drop every non-special key.
            let mut g = STORE.lock();
            g.keys.clear();
            0
        }
        KEYCTL_SET_TIMEOUT => {
            let serial = args.a1 as i32;
            let secs   = args.a2;
            let mut g = STORE.lock();
            let k = match g.keys.get_mut(&serial) {
                Some(k) => k, None => return -(ENOKEY as i64),
            };
            k.expiry_ns = if secs == 0 { 0 } else {
                use hal::TimerOps;
                #[cfg(target_arch = "x86_64")]
                let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
                #[cfg(target_arch = "aarch64")]
                let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
                now.saturating_add(secs.saturating_mul(1_000_000_000))
            };
            0
        }
        KEYCTL_UPDATE => {
            let serial = args.a1 as i32;
            let payload_p = args.a2;
            let plen = args.a3 as usize;
            let payload = match read_user_bytes(payload_p, plen) { Ok(v) => v, Err(rv) => return rv };
            let mut g = STORE.lock();
            let k = match g.keys.get_mut(&serial) {
                Some(k) => k, None => return -(ENOKEY as i64),
            };
            if k.revoked { return -(EKEYREVOKED as i64); }
            k.payload = payload;
            0
        }
        KEYCTL_READ => {
            let serial = args.a1 as i32;
            let buf_p  = args.a2;
            let buflen = args.a3 as usize;
            let g = STORE.lock();
            let k = match g.keys.get(&serial) {
                Some(k) => k, None => return -(ENOKEY as i64),
            };
            if k.revoked { return -(EKEYREVOKED as i64); }
            let want = k.payload.len();
            if buf_p == 0 || buflen == 0 { return want as i64; }
            if buf_p >= hal::USER_VA_END
                || buf_p.checked_add(buflen as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
                return -(Errno::Efault.as_i32() as i64);
            }
            let n = core::cmp::min(buflen, want);
            // SAFETY: buf_p+n validated < USER_VA_END; CPL=0 byte writes through caller's AS, n bytes from kernel-owned payload Vec.
            unsafe {
                for i in 0..n {
                    core::ptr::write_volatile((buf_p + i as u64) as *mut u8, k.payload[i]);
                }
            }
            want as i64
        }
        KEYCTL_DESCRIBE => {
            let serial = args.a1 as i32;
            let buf_p  = args.a2;
            let buflen = args.a3 as usize;
            let g = STORE.lock();
            let k = match g.keys.get(&serial) {
                Some(k) => k, None => return -(ENOKEY as i64),
            };
            // Format: "<type>;<uid>;<gid>;<perm:08x>;<description>".
            let mut s = alloc::format!("{};{};{};{:08x};{}",
                k.key_type, k.uid, k.gid, k.perm, k.description);
            s.push('\0');
            let want = s.len();
            if buf_p == 0 || buflen == 0 { return want as i64; }
            if buf_p >= hal::USER_VA_END
                || buf_p.checked_add(buflen as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
                return -(Errno::Efault.as_i32() as i64);
            }
            let n = core::cmp::min(buflen, want);
            // SAFETY: buf_p+n validated < USER_VA_END; CPL=0 byte writes through caller's AS, n bytes from kernel-owned String.
            unsafe {
                let bytes = s.as_bytes();
                for i in 0..n {
                    core::ptr::write_volatile((buf_p + i as u64) as *mut u8, bytes[i]);
                }
            }
            want as i64
        }
        KEYCTL_SEARCH => {
            let _ring  = args.a1 as i32;
            let type_p = args.a2;
            let desc_p = args.a3;
            let key_type = match read_user_cstr_owned(type_p, 64) { Ok(s) => s, Err(rv) => return rv };
            let description = match read_user_cstr_owned(desc_p, 256) { Ok(s) => s, Err(rv) => return rv };
            let g = STORE.lock();
            for k in g.keys.values() {
                if k.revoked { continue; }
                if k.key_type == key_type && k.description == description {
                    return k.serial as i64;
                }
            }
            -(ENOKEY as i64)
        }
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}
