// Linux keyrings (`add_key` / `request_key` / `keyctl`) — real per-task keyring
// hierarchy. Each task resolves the special keyring ids (`@t/@p/@s/@u/@us`)
// to actual keyring objects; `KEYCTL_JOIN_SESSION_KEYRING` mints a FRESH
// anonymous session keyring (unique serial) or joins a named one, exactly like
// `kernel/security/keys/`. Keys and keyrings share one serial space; a keyring
// is a Key of type "keyring" whose `members` holds the linked child serials.
//
// Module manifest: `perm.rs` owns the Linux `key_task_permission` chokepoint
// (`check_perm`/`visible_for_search`) — every op below calls it, none reads
// `perm`/`uid`/`gid` directly. `ops.rs` owns the per-op testable cores
// (`join_session`, `add_key_core`, `link_core`, `revoke_core`, ... ) driven
// both by hosted tests (`tests.rs`) and by the `sys_*`/`sys_keyctl` entry
// points below, which only parse args, resolve the live caller, and marshal
// user memory.
//
// Model vs Linux (honest scope):
//   * session/thread keyrings are keyed per-TID, the process keyring per-TGID,
//     the user + user-session keyrings per-UID. Lazily created on first
//     reference; fork copies the parent's session serial via `inherit_session`.
//     A login session sharing ONE session keyring across several processes is
//     approximated by per-TID scoping — JOIN replaces the caller's session
//     keyring, which is what pam_keyinit/systemd rely on.
//   * No expiry sweeper (SET_TIMEOUT records but never fires); no DH/PKCS-11
//     key types; "user"/"logon"/"keyring" cover PAM/login/sudo/sshd.
//   * REVOKE marks the slot; later ops return EKEYREVOKED.
//   * Permission model (`perm.rs`): gid match is a single egid, not the full
//     supplementary-group list Linux's `groups_search` walks.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

mod perm;
mod ops;
use ops::{add_key_core, clear_core, describe_core, get_keyring_id, get_persistent, inherit_session,
    join_session, link_core, members_of, read_core, revoke_core, search_core, set_timeout_core,
    setperm_core, unlink_core, update_core};

// keyctl(2) special keyring ids (uapi/linux/keyctl.h). A negative serial
// passed to any op resolves (lazily creating) to the caller's real keyring.
const KEY_SPEC_THREAD_KEYRING:       i32 = -1;
const KEY_SPEC_PROCESS_KEYRING:      i32 = -2;
const KEY_SPEC_SESSION_KEYRING:      i32 = -3;
const KEY_SPEC_USER_KEYRING:         i32 = -4;
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
const KEY_SPEC_GROUP_KEYRING:        i32 = -6;

const ENOKEY:      i32 = 126;
const EKEYREVOKED: i32 = 128;
const KEY_TYPE_MAX: usize = 32;
const KEY_MAX_DESC_SIZE: usize = 4096;

/// The first serial handed out. Serials climb from here so no real key collides
/// with the (removed) legacy sentinel `1`.
const FIRST_SERIAL: i32 = 0x1000_0000;

/// Caller identity a keyctl op resolves special keyrings against, and that
/// `perm::key_permission` checks `uid`/`gid` ownership against. The syscall
/// wrappers fill this from `sched::current`; hosted tests pass it explicitly.
#[derive(Copy, Clone)]
pub struct TaskIds { pub tid: u32, pub tgid: u32, pub uid: u32, pub gid: u32 }

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
    /// For a `keyring`-type key: the serials of its linked members.
    pub members: Vec<i32>,
}

struct Store {
    next_serial: i32,
    keys: BTreeMap<i32, Key>,
    session:  BTreeMap<u32, i32>, // tid  -> session keyring serial
    thread:   BTreeMap<u32, i32>, // tid  -> thread keyring
    process:  BTreeMap<u32, i32>, // tgid -> process keyring
    user:     BTreeMap<u32, i32>, // uid  -> user keyring
    usersess: BTreeMap<u32, i32>, // uid  -> user-session keyring
}

static STORE: Spinlock<Store, TaskListClass> = Spinlock::new(Store {
    next_serial: FIRST_SERIAL,
    keys: BTreeMap::new(),
    session:  BTreeMap::new(),
    thread:   BTreeMap::new(),
    process:  BTreeMap::new(),
    user:     BTreeMap::new(),
    usersess: BTreeMap::new(),
});

impl Store {
    /// Mint a new key/keyring, return its serial. # C: O(log N)
    fn mint(&mut self, key_type: &str, desc: &str, payload: Vec<u8>, uid: u32, gid: u32) -> i32 {
        let serial = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1);
        self.keys.insert(serial, Key {
            serial, key_type: String::from(key_type), description: String::from(desc),
            payload, perm: 0x3f3f0000, uid, gid, expiry_ns: 0, revoked: false, members: Vec::new(),
        });
        serial
    }
    /// Mint a fresh anonymous keyring. # C: O(log N)
    fn new_keyring(&mut self, desc: &str, uid: u32, gid: u32) -> i32 {
        self.mint("keyring", desc, Vec::new(), uid, gid)
    }
    /// Resolve a special (negative) keyring id to a real serial, lazily creating
    /// the caller's keyring. A positive serial passes through; 0 → None. # C: O(log N)
    fn resolve(&mut self, id: i32, t: TaskIds) -> Option<i32> {
        if id >= 0 { return if id == 0 { None } else { Some(id) }; }
        let s = match id {
            KEY_SPEC_THREAD_KEYRING => {
                if let Some(&v) = self.thread.get(&t.tid) { v }
                else { let v = self.new_keyring("_tid", t.uid, t.gid); self.thread.insert(t.tid, v); v }
            }
            KEY_SPEC_PROCESS_KEYRING => {
                if let Some(&v) = self.process.get(&t.tgid) { v }
                else { let v = self.new_keyring("_pid", t.uid, t.gid); self.process.insert(t.tgid, v); v }
            }
            KEY_SPEC_SESSION_KEYRING => {
                if let Some(&v) = self.session.get(&t.tid) { v }
                else { let v = self.new_keyring("_ses", t.uid, t.gid); self.session.insert(t.tid, v); v }
            }
            KEY_SPEC_USER_KEYRING => {
                if let Some(&v) = self.user.get(&t.uid) { v }
                else { let v = self.new_keyring("_uid", t.uid, t.gid); self.user.insert(t.uid, v); v }
            }
            KEY_SPEC_USER_SESSION_KEYRING | KEY_SPEC_GROUP_KEYRING => {
                if let Some(&v) = self.usersess.get(&t.uid) { v }
                else { let v = self.new_keyring("_uus", t.uid, t.gid); self.usersess.insert(t.uid, v); v }
            }
            _ => return None,
        };
        Some(s)
    }
    /// Link `child` into `ring` (a keyring), idempotently. # C: O(members)
    fn link(&mut self, ring: i32, child: i32) -> Result<(), i32> {
        if !self.keys.contains_key(&child) { return Err(ENOKEY); }
        match self.keys.get_mut(&ring) {
            Some(k) if k.key_type == "keyring" => {
                if !k.members.contains(&child) { k.members.push(child); }
                Ok(())
            }
            Some(_) => Err(Errno::Enotdir.as_i32()),
            None => Err(ENOKEY),
        }
    }
}

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

fn read_user_bytes(p: u64, len: usize) -> Result<Vec<u8>, i64> {
    if len == 0 { return Ok(Vec::new()); }
    validate_user_buf(p, len as u64, 1)?;
    let mut out = alloc::vec![0u8; len];
    // SAFETY: exact user byte range validated; destination is a kernel-owned Vec.
    unsafe { for i in 0..len { out[i] = core::ptr::read_unaligned((p + i as u64) as *const u8); } }
    Ok(out)
}

fn write_user_prefix(p: u64, src: &[u8], limit: usize) -> Result<(), i64> {
    let n = core::cmp::min(limit, src.len());
    if n == 0 { return Ok(()); }
    validate_user_buf_writable(p, n as u64, 1)?;
    // SAFETY: copied byte prefix is writable-user validated; source is kernel-owned.
    unsafe { for i in 0..n { core::ptr::write_unaligned((p + i as u64) as *mut u8, src[i]); } }
    Ok(())
}

/// Current task identity for keyctl special-keyring resolution. Falls back to
/// uid/gid 0 with tid/tgid 0 pre-sched (boot). # C: O(1)
fn cur_ids() -> TaskIds {
    use core::sync::atomic::Ordering::Acquire;
    match sched::current() {
        Some(c) => TaskIds {
            tid: c.tid, tgid: c.vtgid.load(Acquire),
            uid: c.creds.euid.load(Acquire), gid: c.creds.egid.load(Acquire),
        },
        None => TaskIds { tid: 0, tgid: 0, uid: 0, gid: 0 },
    }
}

/// Does the live caller hold `CAP_SYS_ADMIN` — the one bypass Linux grants for
/// SETATTR-class ops (`KEYCTL_SETPERM`, `KEYCTL_SET_TIMEOUT`). # C: O(1)
fn cur_is_sys_admin() -> bool {
    sched::current().map(|c| c.has_cap(sched::cap::SYS_ADMIN)).unwrap_or(false)
}

/// `sys_add_key(type, desc, payload, plen, keyring)` — slot 217. # C: O(N)
pub fn sys_add_key(args: &SyscallArgs) -> i64 {
    let key_type = match read_user_key_type(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let description = match read_user_key_desc(args.a1) { Ok(s) => s, Err(rv) => return rv };
    let payload = match read_user_bytes(args.a2, args.a3 as usize) { Ok(v) => v, Err(rv) => return rv };
    add_key_core(cur_ids(), &key_type, &description, payload, args.a4 as i32)
}

/// `sys_request_key(type, desc, callout, dest)` — slot 218. No callout helper,
/// so a miss is ENOKEY. # C: O(N)
pub fn sys_request_key(args: &SyscallArgs) -> i64 {
    let key_type = match read_user_key_type(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let description = match read_user_key_desc(args.a1) { Ok(s) => s, Err(rv) => return rv };
    search_core(cur_ids(), &key_type, &description)
}

const KEYCTL_GET_KEYRING_ID:       u64 = 0;
const KEYCTL_JOIN_SESSION_KEYRING: u64 = 1;
const KEYCTL_UPDATE:               u64 = 2;
const KEYCTL_REVOKE:               u64 = 3;
const KEYCTL_SETPERM:              u64 = 5;
const KEYCTL_DESCRIBE:             u64 = 6;
const KEYCTL_CLEAR:                u64 = 7;
const KEYCTL_LINK:                 u64 = 8;
const KEYCTL_UNLINK:               u64 = 9;
const KEYCTL_SEARCH:               u64 = 10;
const KEYCTL_READ:                 u64 = 11;
const KEYCTL_SET_TIMEOUT:          u64 = 15;
const KEYCTL_SET_REQKEY_KEYRING:   u64 = 14;
const KEYCTL_GET_PERSISTENT:       u64 = 22;

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

/// Read the monotonic clock for `KEYCTL_SET_TIMEOUT`. Arch-gated so the
/// hosted-testable `ops::set_timeout_core` stays cfg-free. # C: O(1)
fn monotonic_now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(target_os = "oxide-kernel"))] { 0u64 }
}

/// `sys_keyctl(op, arg2..arg5)` — slot 219. Parses args, resolves the live
/// caller, and delegates every op to its `ops::*_core` — see the module
/// manifest at the top of this file. # C: depends on op
pub fn sys_keyctl(args: &SyscallArgs) -> i64 {
    let t = cur_ids();
    match args.a0 {
        KEYCTL_JOIN_SESSION_KEYRING => {
            let name = if args.a1 == 0 { None }
                       else { match read_user_key_desc(args.a1) { Ok(s) => Some(s), Err(rv) => return rv } };
            join_session(t, name.as_deref()) as i64
        }
        KEYCTL_GET_KEYRING_ID => get_keyring_id(t, args.a1 as i32, args.a2 != 0),
        KEYCTL_SET_REQKEY_KEYRING => 0,
        KEYCTL_GET_PERSISTENT => get_persistent(t),
        KEYCTL_LINK => link_core(t, args.a1 as i32, args.a2 as i32),
        KEYCTL_UNLINK => unlink_core(t, args.a1 as i32, args.a2 as i32),
        KEYCTL_REVOKE => revoke_core(t, args.a1 as i32),
        KEYCTL_CLEAR => clear_core(t, args.a1 as i32),
        KEYCTL_SET_TIMEOUT => set_timeout_core(t, args.a1 as i32, args.a2, monotonic_now_ns(), cur_is_sys_admin()),
        KEYCTL_UPDATE => {
            let payload = match read_user_bytes(args.a2, args.a3 as usize) { Ok(v) => v, Err(rv) => return rv };
            update_core(t, args.a1 as i32, payload)
        }
        KEYCTL_SETPERM => setperm_core(t, args.a1 as i32, args.a2 as u32, cur_is_sys_admin()),
        KEYCTL_READ => {
            let (buf_p, buflen) = (args.a2, args.a3 as usize);
            let bytes = match read_core(t, args.a1 as i32) { Ok(b) => b, Err(rv) => return rv };
            let want = bytes.len();
            if buf_p == 0 || buflen == 0 { return want as i64; }
            if let Err(rv) = write_user_prefix(buf_p, &bytes, buflen) { return rv; }
            want as i64
        }
        KEYCTL_DESCRIBE => {
            let (buf_p, buflen) = (args.a2, args.a3 as usize);
            let s = match describe_core(t, args.a1 as i32) { Ok(s) => s, Err(rv) => return rv };
            let want = s.len();
            if buf_p == 0 || buflen == 0 { return want as i64; }
            if let Err(rv) = write_user_prefix(buf_p, s.as_bytes(), buflen) { return rv; }
            want as i64
        }
        KEYCTL_SEARCH => {
            let key_type = match read_user_key_type(args.a2) { Ok(s) => s, Err(rv) => return rv };
            let description = match read_user_key_desc(args.a3) { Ok(s) => s, Err(rv) => return rv };
            search_core(t, &key_type, &description)
        }
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod perm_tests;
