// Per-op cores for `add_key`/`request_key`/`keyctl`. Each takes an explicit
// `TaskIds` (and, for SETATTR-class ops, an explicit `admin` bool) instead of
// reading `sched::current()` — hosted tests drive these directly to prove
// enforcement for an arbitrary caller identity; `sys_add_key`/`sys_request_key`/
// `sys_keyctl` in `../keyring.rs` are thin wrappers that parse args, resolve
// the live caller, marshal user memory, and call these. This is the ONLY place
// each op's logic runs — no duplicate copy in the syscall entry points.

use alloc::string::String;
use alloc::vec::Vec;

use super::{ENOKEY, EKEYREVOKED, KEY_SPEC_SESSION_KEYRING, KEY_SPEC_THREAD_KEYRING,
    KEY_SPEC_PROCESS_KEYRING, KEY_SPEC_USER_KEYRING, KEY_SPEC_USER_SESSION_KEYRING,
    KEY_SPEC_GROUP_KEYRING, STORE, TaskIds};
use super::perm::{check_perm, visible_for_search, KEY_NEED_LINK, KEY_NEED_READ,
    KEY_NEED_SETATTR, KEY_NEED_VIEW, KEY_NEED_WRITE};

/// `KEYCTL_JOIN_SESSION_KEYRING`: `name==None` → mint a FRESH anonymous session
/// keyring; `Some(n)` → join the existing named session keyring or mint it.
/// Sets the caller's session keyring, returns its serial. # C: O(N)
pub fn join_session(t: TaskIds, name: Option<&str>) -> i32 {
    let mut g = STORE.lock();
    let serial = match name {
        None => g.new_keyring("_ses", t.uid, t.gid),
        Some(n) => {
            let found = g.keys.values()
                .find(|k| k.key_type == "keyring" && k.description == n && !k.revoked)
                .map(|k| k.serial);
            match found { Some(s) => s, None => g.new_keyring(n, t.uid, t.gid) }
        }
    };
    g.session.insert(t.tid, serial);
    serial
}

/// `KEYCTL_GET_KEYRING_ID(id, create)` core: resolve a special/real id.
/// `create==false` on a not-yet-present keyring → ENOKEY. # C: O(N)
pub fn get_keyring_id(t: TaskIds, id: i32, create: bool) -> i64 {
    let mut g = STORE.lock();
    if id < 0 && !create {
        let present = match id {
            KEY_SPEC_THREAD_KEYRING       => g.thread.contains_key(&t.tid),
            KEY_SPEC_PROCESS_KEYRING      => g.process.contains_key(&t.tgid),
            KEY_SPEC_SESSION_KEYRING      => g.session.contains_key(&t.tid),
            KEY_SPEC_USER_KEYRING         => g.user.contains_key(&t.uid),
            KEY_SPEC_USER_SESSION_KEYRING | KEY_SPEC_GROUP_KEYRING => g.usersess.contains_key(&t.uid),
            _ => false,
        };
        if !present { return -(ENOKEY as i64); }
    }
    match g.resolve(id, t) { Some(s) => s as i64, None => -(ENOKEY as i64) }
}

/// `KEYCTL_GET_PERSISTENT` core: resolve (lazily create) the caller's user
/// keyring. # C: O(log N)
pub fn get_persistent(t: TaskIds) -> i64 {
    let mut g = STORE.lock();
    match g.resolve(KEY_SPEC_USER_KEYRING, t) { Some(s) => s as i64, None => -(ENOKEY as i64) }
}

/// Add a key into the destination keyring (special id resolved), returning the
/// new key serial. Default destination = the session keyring. Linux
/// `add_key()`: the destination keyring needs `KEY_NEED_WRITE`, checked
/// BEFORE the new key is minted. # C: O(N)
pub fn add_key_core(t: TaskIds, key_type: &str, desc: &str, payload: Vec<u8>, dest: i32) -> i64 {
    let mut g = STORE.lock();
    let ring_id = if dest == 0 { KEY_SPEC_SESSION_KEYRING } else { dest };
    let ring = match g.resolve(ring_id, t) { Some(r) => r, None => return -(ENOKEY as i64) };
    if let Err(rv) = check_perm(&g, ring, t, KEY_NEED_WRITE, false) { return rv; }
    let serial = g.mint(key_type, desc, payload, t.uid, t.gid);
    let _ = g.link(ring, serial);
    serial as i64
}

/// `KEYCTL_LINK` core: resolve BOTH the child key and the destination keyring
/// before linking. Special ids (e.g. `KEY_SPEC_USER_KEYRING`) are created on
/// demand, mirroring Linux `lookup_user_key(..., KEY_LOOKUP_CREATE)`. pam_keyinit
/// links the user keyring (`-4`) into the session keyring (`-3`); passing the raw
/// special id `-4` as the child made `link()` return ENOKEY (no key has serial
/// `-4`), so gdm/PAM logged "Failed to link user keyring into session keyring:
/// Required key not available". Linux `keyctl_keyring_link`: child needs
/// `KEY_NEED_LINK`, destination ring needs `KEY_NEED_WRITE`. # C: O(N)
pub fn link_core(t: TaskIds, child: i32, ring: i32) -> i64 {
    let mut g = STORE.lock();
    let c = match g.resolve(child, t) { Some(c) => c, None => return -(ENOKEY as i64) };
    let r = match g.resolve(ring, t)  { Some(r) => r, None => return -(ENOKEY as i64) };
    if let Err(rv) = check_perm(&g, c, t, KEY_NEED_LINK, false) { return rv; }
    if let Err(rv) = check_perm(&g, r, t, KEY_NEED_WRITE, false) { return rv; }
    match g.link(r, c) { Ok(()) => 0, Err(e) => -(e as i64) }
}

/// `KEYCTL_UNLINK` core: resolve child + ring (same as [`link_core`]), then drop
/// the child from the ring's member list. ENOKEY if the child was not a member.
/// Linux `keyctl_keyring_unlink`: only the destination ring needs
/// `KEY_NEED_WRITE`. # C: O(members)
pub fn unlink_core(t: TaskIds, child: i32, ring: i32) -> i64 {
    let mut g = STORE.lock();
    let c = match g.resolve(child, t) { Some(c) => c, None => return -(ENOKEY as i64) };
    let r = match g.resolve(ring, t)  { Some(r) => r, None => return -(ENOKEY as i64) };
    if let Err(rv) = check_perm(&g, r, t, KEY_NEED_WRITE, false) { return rv; }
    match g.keys.get_mut(&r) {
        Some(k) if k.key_type == "keyring" => {
            let before = k.members.len();
            k.members.retain(|&m| m != c);
            if k.members.len() == before { -(ENOKEY as i64) } else { 0 }
        }
        _ => -(ENOKEY as i64),
    }
}

/// `KEYCTL_REVOKE` core: `KEY_NEED_WRITE` on the key. # C: O(log N)
pub fn revoke_core(t: TaskIds, serial: i32) -> i64 {
    let mut g = STORE.lock();
    if let Err(rv) = check_perm(&g, serial, t, KEY_NEED_WRITE, false) { return rv; }
    match g.keys.get_mut(&serial) { Some(k) => { k.revoked = true; 0 } None => -(ENOKEY as i64) }
}

/// `KEYCTL_CLEAR` core: `KEY_NEED_WRITE` on the resolved keyring. # C: O(members)
pub fn clear_core(t: TaskIds, ring_id: i32) -> i64 {
    let mut g = STORE.lock();
    let r = match g.resolve(ring_id, t) { Some(r) => r, None => return -(ENOKEY as i64) };
    if let Err(rv) = check_perm(&g, r, t, KEY_NEED_WRITE, false) { return rv; }
    match g.keys.get_mut(&r) {
        Some(k) if k.key_type == "keyring" => { k.members.clear(); 0 }
        _ => -(ENOKEY as i64),
    }
}

/// `KEYCTL_SET_TIMEOUT` core: `KEY_NEED_SETATTR` on the key (`admin` bypasses).
/// `now_ns` is the monotonic clock read by the caller — kept out of this
/// hosted-testable core so it stays arch/cfg-free. # C: O(log N)
pub fn set_timeout_core(t: TaskIds, serial: i32, secs: u64, now_ns: u64, admin: bool) -> i64 {
    let mut g = STORE.lock();
    if let Err(rv) = check_perm(&g, serial, t, KEY_NEED_SETATTR, admin) { return rv; }
    let k = match g.keys.get_mut(&serial) { Some(k) => k, None => return -(ENOKEY as i64) };
    k.expiry_ns = if secs == 0 { 0 } else { now_ns.saturating_add(secs.saturating_mul(1_000_000_000)) };
    0
}

/// `KEYCTL_UPDATE` core: `KEY_NEED_WRITE` on the key. # C: O(payload)
pub fn update_core(t: TaskIds, serial: i32, payload: Vec<u8>) -> i64 {
    let mut g = STORE.lock();
    if let Err(rv) = check_perm(&g, serial, t, KEY_NEED_WRITE, false) { return rv; }
    let k = g.keys.get_mut(&serial).expect("check_perm proved existence under the same held lock");
    if k.revoked { return -(EKEYREVOKED as i64); }
    k.payload = payload; 0
}

/// `KEYCTL_SETPERM` core: `KEY_NEED_SETATTR` on the key (`admin` bypasses).
/// # C: O(log N)
pub fn setperm_core(t: TaskIds, serial: i32, perm: u32, admin: bool) -> i64 {
    let mut g = STORE.lock();
    if let Err(rv) = check_perm(&g, serial, t, KEY_NEED_SETATTR, admin) { return rv; }
    match g.keys.get_mut(&serial) { Some(k) => { k.perm = perm; 0 } None => -(ENOKEY as i64) }
}

/// `KEYCTL_READ` core: `KEY_NEED_READ` on the key. Returns the raw bytes to
/// write to userspace (keyring: native-endian 4-byte member serials; else:
/// the payload) as an already-negated errno on failure. # C: O(payload/members)
pub fn read_core(t: TaskIds, serial: i32) -> Result<Vec<u8>, i64> {
    let g = STORE.lock();
    check_perm(&g, serial, t, KEY_NEED_READ, false)?;
    let k = g.keys.get(&serial).expect("check_perm proved existence under the same held lock");
    if k.revoked { return Err(-(EKEYREVOKED as i64)); }
    Ok(if k.key_type == "keyring" {
        let mut v = Vec::with_capacity(k.members.len() * 4);
        for &m in &k.members { v.extend_from_slice(&m.to_ne_bytes()); }
        v
    } else { k.payload.clone() })
}

/// `KEYCTL_DESCRIBE` core: `KEY_NEED_VIEW` on the key. Returns the
/// `type;uid;gid;perm;desc\0` descriptor string. # C: O(log N)
pub fn describe_core(t: TaskIds, serial: i32) -> Result<String, i64> {
    let g = STORE.lock();
    check_perm(&g, serial, t, KEY_NEED_VIEW, false)?;
    let k = g.keys.get(&serial).expect("check_perm proved existence under the same held lock");
    let mut s = alloc::format!("{};{};{};{:08x};{}", k.key_type, k.uid, k.gid, k.perm, k.description);
    s.push('\0');
    Ok(s)
}

/// Snapshot a keyring's member serials (Linux `KEYCTL_READ` on a keyring, used
/// by tests). `None` if the serial isn't a keyring. # C: O(members)
pub fn members_of(serial: i32) -> Option<Vec<i32>> {
    let g = STORE.lock();
    g.keys.get(&serial).filter(|k| k.key_type == "keyring").map(|k| k.members.clone())
}

/// Copy the parent's session keyring serial to a forked child (Linux shares the
/// session keyring across fork). # C: O(log N)
pub fn inherit_session(parent_tid: u32, child_tid: u32) {
    let mut g = STORE.lock();
    if let Some(&s) = g.session.get(&parent_tid) { g.session.insert(child_tid, s); }
}

/// Shared `KEYCTL_SEARCH`/`sys_request_key` core: first non-revoked type+desc
/// match the caller can `KEY_NEED_SEARCH`. A match without SEARCH permission
/// never matches — invisible, not merely denied (Linux hides existence from
/// keyring search). # C: O(N)
pub fn search_core(t: TaskIds, key_type: &str, description: &str) -> i64 {
    let g = STORE.lock();
    for k in g.keys.values() {
        if !k.revoked && k.key_type == key_type && k.description == description && visible_for_search(&g, k, t) {
            return k.serial as i64;
        }
    }
    -(ENOKEY as i64)
}
