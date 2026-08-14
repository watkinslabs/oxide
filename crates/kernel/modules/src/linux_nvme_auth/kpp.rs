use core::ffi::c_void;
use core::ptr;
use crate::linux_dma::{self, ScatterList};

const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const KPP_TFM_BASE_OFF: usize = 8;
const KPP_ALG_OFF: usize = KPP_TFM_BASE_OFF + 32;
const ASYNC_TFM_OFF: usize = 24;

#[repr(C)]
struct KppRequest { base: [u8; 48], src: *mut ScatterList, dst: *mut ScatterList, src_len: u32, dst_len: u32 }
#[repr(C)]
struct CryptoKpp { _head: [u8; KPP_ALG_OFF], alg: *const KppAlg }
#[repr(C)]
struct KppAlg { set_secret: usize, generate_public: usize, compute_shared: usize }

type SetSecret = unsafe extern "C" fn(*mut CryptoKpp, *const c_void, u32) -> i32;
type KppOp = unsafe extern "C" fn(*mut KppRequest) -> i32;

/// Register direct KPP helper calls used by NVMe DHCHAP.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("nvme_auth_gen_privkey", nvme_auth_gen_privkey as *const () as usize),
        ("nvme_auth_gen_pubkey", nvme_auth_gen_pubkey as *const () as usize),
        ("nvme_auth_gen_shared_secret", nvme_auth_gen_shared_secret as *const () as usize),
    ] { export(name, addr, true); }
}

extern "C" fn nvme_auth_gen_privkey(tfm: *mut CryptoKpp, _gid: u8) -> i32 {
    let Some(alg) = alg(tfm) else { return -EINVAL; }; let Some(call) = fn_set(alg.set_secret) else { return -EINVAL; };
    // SAFETY: KPP transform and its standard set_secret callback were validated above.
    unsafe { call(tfm, ptr::null(), 0) }
}
extern "C" fn nvme_auth_gen_pubkey(tfm: *mut CryptoKpp, host: *mut u8, host_len: usize) -> i32 {
    if host.is_null() || host_len > u32::MAX as usize { return -EINVAL; } let Some(alg) = alg(tfm) else { return -EINVAL; }; let Some(call) = fn_op(alg.generate_public) else { return -EINVAL; };
    let mut dst = ScatterList { page_link: 0, offset: 0, length: 0, dma_address: 0, dma_length: 0 };
    linux_dma::sg_set_buf(&mut dst, host.cast(), host_len as u32); let mut req = request(tfm, ptr::null_mut(), &mut dst, 0, host_len as u32);
    // SAFETY: KPP callback receives standard request and one output scatterlist entry.
    unsafe { call(&mut req) }
}
extern "C" fn nvme_auth_gen_shared_secret(tfm: *mut CryptoKpp, ctrl: *mut u8, ctrl_len: usize, sess: *mut u8, sess_len: usize) -> i32 {
    if ctrl.is_null() || sess.is_null() || ctrl_len > u32::MAX as usize || sess_len > u32::MAX as usize { return -EINVAL; } let Some(alg) = alg(tfm) else { return -EINVAL; }; let Some(call) = fn_op(alg.compute_shared) else { return -EINVAL; };
    let mut src = ScatterList { page_link: 0, offset: 0, length: 0, dma_address: 0, dma_length: 0 }; let mut dst = ScatterList { page_link: 0, offset: 0, length: 0, dma_address: 0, dma_length: 0 };
    linux_dma::sg_set_buf(&mut src, ctrl.cast(), ctrl_len as u32); linux_dma::sg_set_buf(&mut dst, sess.cast(), sess_len as u32); let mut req = request(tfm, &mut src, &mut dst, ctrl_len as u32, sess_len as u32);
    // SAFETY: KPP callback receives standard request and one source/destination scatterlist entry.
    unsafe { call(&mut req) }
}
fn alg(tfm: *mut CryptoKpp) -> Option<&'static KppAlg> { if tfm.is_null() { return None; } // SAFETY: tfm points at standard crypto_kpp storage.
    unsafe { (*tfm).alg.as_ref() } }
fn request(tfm: *mut CryptoKpp, src: *mut ScatterList, dst: *mut ScatterList, src_len: u32, dst_len: u32) -> KppRequest { let mut r = KppRequest { base: [0; 48], src, dst, src_len, dst_len }; let p = (tfm.cast::<u8>().wrapping_add(KPP_TFM_BASE_OFF)) as usize; r.base[ASYNC_TFM_OFF..ASYNC_TFM_OFF + core::mem::size_of::<usize>()].copy_from_slice(&p.to_ne_bytes()); r }
fn fn_set(addr: usize) -> Option<SetSecret> { if addr == 0 { None } else { // SAFETY: KPP algorithm table stores a set_secret function address at this offset.
    Some(unsafe { core::mem::transmute(addr) }) } }
fn fn_op(addr: usize) -> Option<KppOp> { if addr == 0 { None } else { // SAFETY: KPP algorithm table stores a KPP operation function address at this offset.
    Some(unsafe { core::mem::transmute(addr) }) } }

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    static CALLS: AtomicU32 = AtomicU32::new(0);
    unsafe extern "C" fn set_secret(_tfm: *mut CryptoKpp, key: *const c_void, len: u32) -> i32 { if key.is_null() && len == 0 { CALLS.fetch_or(1, Ordering::SeqCst); 0 } else { -EINVAL } }
    unsafe extern "C" fn public(req: *mut KppRequest) -> i32 { // SAFETY: test invokes this with the wrapper's initialized one-entry request.
        unsafe { let dst = &mut *(*req).dst; let p = dst.dma_address as *mut u8; *p = 0x51; } CALLS.fetch_or(2, Ordering::SeqCst); 0 }
    unsafe extern "C" fn shared(req: *mut KppRequest) -> i32 { // SAFETY: test invokes this with the wrapper's initialized one-entry source/destination request.
        unsafe { let src = &*(*req).src; let dst = &*(*req).dst; let input = core::slice::from_raw_parts(src.dma_address as *const u8, (*req).src_len as usize); let output = core::slice::from_raw_parts_mut(dst.dma_address as *mut u8, (*req).dst_len as usize); output[..input.len()].copy_from_slice(input); } CALLS.fetch_or(4, Ordering::SeqCst); 0 }
    #[test] fn request_uses_kernel_kpp_layout() { assert_eq!(core::mem::size_of::<KppRequest>(), 72); assert_eq!(core::mem::offset_of!(KppRequest, src), 48); assert_eq!(core::mem::offset_of!(CryptoKpp, alg), 40); }
    #[test] fn wrappers_invoke_the_standard_callbacks() { let _modules = crate::test_serial::claim(); CALLS.store(0, Ordering::SeqCst); let alg = KppAlg { set_secret: set_secret as *const () as usize, generate_public: public as *const () as usize, compute_shared: shared as *const () as usize }; let mut tfm = CryptoKpp { _head: [0; KPP_ALG_OFF], alg: &alg }; assert_eq!(nvme_auth_gen_privkey(&mut tfm, 1), 0); let mut pubkey = [0u8; 1]; assert_eq!(nvme_auth_gen_pubkey(&mut tfm, pubkey.as_mut_ptr(), 1), 0); let mut out = [0u8; 3]; assert_eq!(nvme_auth_gen_shared_secret(&mut tfm, b"abc".as_ptr().cast_mut(), 3, out.as_mut_ptr(), 3), 0); assert_eq!(pubkey, [0x51]); assert_eq!(out, *b"abc"); assert_eq!(CALLS.load(Ordering::SeqCst), 7); }
}
