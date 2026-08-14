// Native NVMe key ABI entry points. The canonical keyring owner installs the
// implementation before module exports become visible; this layer supplies
// only module-loader-facing C symbols and never stores key state.

use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

pub type KeyPutHook = extern "C" fn(*mut c_void);
pub type KeyRevokeHook = extern "C" fn(*mut c_void);
pub type RefreshHook = extern "C" fn(*mut c_void, *const c_char, *const c_char, u8, *mut u8, usize, *const c_char) -> *mut c_void;

static PUT: AtomicPtr<()> = AtomicPtr::new(null_mut());
static REVOKE: AtomicPtr<()> = AtomicPtr::new(null_mut());
static REFRESH: AtomicPtr<()> = AtomicPtr::new(null_mut());

pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr, gpl) in [
        ("key_put", key_put as *const () as usize, false),
        ("key_revoke", key_revoke as *const () as usize, false),
        ("nvme_tls_psk_refresh", nvme_tls_psk_refresh as *const () as usize, true),
    ] { export(name, addr, gpl); }
}

pub(super) fn install_hooks(put: KeyPutHook, revoke: KeyRevokeHook, refresh: RefreshHook) {
    PUT.store(put as *mut (), Ordering::Release);
    REVOKE.store(revoke as *mut (), Ordering::Release);
    REFRESH.store(refresh as *mut (), Ordering::Release);
}

extern "C" fn key_put(key: *mut c_void) {
    let hook = PUT.load(Ordering::Acquire);
    if hook.is_null() { return; }
    // SAFETY: install_hooks publishes a function pointer with this exact ABI before module loading.
    unsafe { core::mem::transmute::<*mut (), KeyPutHook>(hook)(key); }
}

extern "C" fn key_revoke(key: *mut c_void) {
    let hook = REVOKE.load(Ordering::Acquire);
    if hook.is_null() { return; }
    // SAFETY: install_hooks publishes a function pointer with this exact ABI before module loading.
    unsafe { core::mem::transmute::<*mut (), KeyRevokeHook>(hook)(key); }
}

extern "C" fn nvme_tls_psk_refresh(keyring: *mut c_void, hostnqn: *const c_char,
    subnqn: *const c_char, hmac_id: u8, data: *mut u8, data_len: usize, digest: *const c_char) -> *mut c_void
{
    let hook = REFRESH.load(Ordering::Acquire);
    if hook.is_null() { return err_enokey(); }
    // SAFETY: install_hooks publishes a function pointer with this exact ABI before module loading.
    unsafe { core::mem::transmute::<*mut (), RefreshHook>(hook)(keyring, hostnqn, subnqn, hmac_id, data, data_len, digest) }
}

fn err_enokey() -> *mut c_void { (0usize.wrapping_sub(126)) as *mut c_void }

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CALL: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn put(_: *mut c_void) { CALL.fetch_add(1, Ordering::Relaxed); }
    extern "C" fn revoke(_: *mut c_void) { CALL.fetch_add(10, Ordering::Relaxed); }
    extern "C" fn refresh(_: *mut c_void, _: *const c_char, _: *const c_char, _: u8, _: *mut u8, _: usize, _: *const c_char) -> *mut c_void { 42usize as *mut c_void }
    #[test]
    fn exports_forward_to_the_canonical_owner() {
        let _modules = crate::test_serial::claim();
        CALL.store(0, Ordering::Relaxed); install_hooks(put, revoke, refresh);
        key_put(null_mut()); key_revoke(null_mut());
        assert_eq!(CALL.load(Ordering::Relaxed), 11);
        assert_eq!(nvme_tls_psk_refresh(null_mut(), core::ptr::null(), core::ptr::null(), 0, null_mut(), 0, core::ptr::null()) as usize, 42);
    }
}
