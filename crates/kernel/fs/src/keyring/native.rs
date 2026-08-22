// Native-driver key ABI bridge. The keyring store remains the single owner of
// key identity, payload, revocation and expiry; these handles only carry a
// temporary native-driver reference to one store serial.

use alloc::boxed::Box;
use core::ffi::{c_char, c_void, CStr};
use core::sync::atomic::{AtomicUsize, Ordering};

use super::store::{KeyNs, Store, TaskIds, STORE};
use super::types;
use super::uapi::*;

const HANDLE_TAG: u64 = 0x4f58_4944_454b_4559;
const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;
const ENOKEY: i32 = 126;
const TLS_KEY_LIFETIME_SECS: u64 = 3600;
const NSEC_PER_SEC: u64 = 1_000_000_000;
const NATIVE_ROOT_PERM: u32 = (KEY_POS_ALL & !KEY_POS_SETATTR)
    | (KEY_USR_ALL & !(KEY_NEED_SETATTR << KEY_PERM_USR_SHIFT));

#[repr(C)]
pub struct NativeKey { tag: u64, refs: AtomicUsize, serial: i32 }

/// Drop one native-driver reference to a canonical key. # C: O(1)
pub extern "C" fn key_put(key: *mut c_void) {
    if key.is_null() { return; }
    let key = key.cast::<NativeKey>();
    // SAFETY: native key callers pass the opaque handle this module returned.
    let valid = unsafe { (*key).tag == HANDLE_TAG };
    if !valid { return; }
    // SAFETY: a valid handle has an initialized reference count owned by this bridge.
    if unsafe { (*key).refs.fetch_sub(1, Ordering::AcqRel) } == 1 {
        // SAFETY: the final reference uniquely owns the allocation.
        unsafe { drop(Box::from_raw(key)); }
    }
}

/// Revoke the canonical key named by a native-driver handle. # C: O(log N)
pub extern "C" fn key_revoke(key: *mut c_void) {
    let Some(serial) = serial_of(key) else { return; };
    let mut g = STORE.lock();
    let Some(k) = g.keys.get_mut(&serial) else { return; };
    if k.revoked { return; }
    k.revoked = true;
    k.payload.fill(0);
    k.payload.clear();
}

/// Refresh the generated TLS PSK in the canonical NVMe keyring. # C: O(log N + payload)
pub extern "C" fn nvme_tls_psk_refresh(keyring: *mut c_void, hostnqn: *const c_char,
    subnqn: *const c_char, hmac_id: u8, data: *mut u8, data_len: usize, digest: *const c_char) -> *mut c_void
{
    let (Some(host), Some(subsys), Some(digest)) = (cstr(hostnqn), cstr(subnqn), cstr(digest)) else { return err(EINVAL); };
    if data.is_null() || data_len == 0 { return err(EINVAL); }
    let (Ok(host), Ok(subsys), Ok(digest)) = (core::str::from_utf8(host), core::str::from_utf8(subsys), core::str::from_utf8(digest)) else { return err(EINVAL); };
    // SAFETY: non-null data names exactly data_len bytes owned by the native caller for this call.
    let data = unsafe { core::slice::from_raw_parts(data, data_len) };
    let mut g = STORE.lock();
    let ring = match keyring_serial(&g, keyring) {
        Some(s) => s,
        None if keyring.is_null() => match default_ring(&mut g) { Ok(s) => s, Err(e) => return err(e) },
        None => return err(ENOKEY),
    };
    let identity = alloc::format!("NVMe1G{:02} {} {} {}", hmac_id, host, subsys, digest);
    let ty = types::lookup("psk").expect("psk key type is registered");
    let ns = KeyNs::of(&TaskIds::default(), ty);
    let serial = match g.keys[&ring].members.iter().copied().find(|s| g.keys.get(s).is_some_and(|k|
        core::ptr::eq(k.key_type, ty) && k.description == identity && k.domain == ns.domain && !k.invalidated)) {
        Some(s) => {
            let k = g.keys.get_mut(&s).expect("member serial names a live key");
            k.payload.fill(0); k.payload = data.to_vec(); k.revoked = false; s
        }
        None => match g.mint_payload_not_in_quota(ty, &identity, data.to_vec(), 0, 0, NATIVE_ROOT_PERM, ns) {
            Ok(s) => match g.link(ring, s) { Ok(()) => s, Err(_) => { g.destroy(s); return err(ENOKEY); } },
            Err(_) => return err(ENOMEM),
        },
    };
    let k = g.keys.get_mut(&serial).expect("created or updated key remains in the held store");
    k.expiry_ns = super::monotonic_now_ns().saturating_add(TLS_KEY_LIFETIME_SECS.saturating_mul(NSEC_PER_SEC));
    handle(serial).cast()
}

/// The canonical NVMe keyring, created on first use. It hangs off no other
/// keyring and no task owns it, so it carries the kernel's own reference —
/// without it the collector reaps the ring, and every PSK in it, the first
/// time anything in the system triggers a collection.
fn default_ring(g: &mut Store) -> Result<i32, i32> {
    if let Some(s) = g.keys.iter().find_map(|(&s, k)| (k.is_keyring() && k.description == ".nvme").then_some(s)) { return Ok(s); }
    let s = g.mint_not_in_quota(types::keyring_type(), ".nvme", 0, 0, NATIVE_ROOT_PERM,
        KeyNs::of(&TaskIds::default(), types::keyring_type())).map_err(|_| ENOMEM)?;
    g.keys.get_mut(&s).expect("just minted under the held lock").kernel_held = true;
    Ok(s)
}

fn keyring_serial(g: &Store, p: *mut c_void) -> Option<i32> {
    let serial = serial_of(p)?;
    g.keys.get(&serial).filter(|k| k.is_keyring() && !k.revoked && !k.invalidated).map(|_| serial)
}

fn serial_of(p: *mut c_void) -> Option<i32> {
    if p.is_null() { return None; }
    let p = p.cast::<NativeKey>();
    // SAFETY: native callers may only hand back opaque bridge handles.
    unsafe { ((*p).tag == HANDLE_TAG).then_some((*p).serial) }
}

fn handle(serial: i32) -> *mut NativeKey {
    Box::into_raw(Box::new(NativeKey { tag: HANDLE_TAG, refs: AtomicUsize::new(1), serial }))
}

fn cstr<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() { return None; }
    // SAFETY: ABI contract requires a NUL-terminated C string valid for this call.
    Some(unsafe { CStr::from_ptr(p).to_bytes() })
}

fn err(errno: i32) -> *mut c_void { (0usize.wrapping_sub(errno as usize)) as *mut c_void }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refresh_updates_then_revoke_wipes_the_canonical_payload() {
        let p = nvme_tls_psk_refresh(core::ptr::null_mut(), c"nqn.2014-08.org.nvmexpress:host".as_ptr(), c"nqn.2014-08.org.nvmexpress:subsys".as_ptr(), 1, b"secret".as_ptr().cast_mut(), 6, c"digest".as_ptr());
        assert!((p as usize) < usize::MAX - 4095);
        let s = serial_of(p).unwrap();
        STORE.lock().collect();
        assert_eq!(STORE.lock().keys[&s].payload, b"secret");
        key_revoke(p); assert!(STORE.lock().keys[&s].revoked);
        assert!(STORE.lock().keys[&s].payload.is_empty());
        key_put(p);
    }
}
