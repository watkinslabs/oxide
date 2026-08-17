extern crate alloc;

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr;

use mpi::Mpi;

use crate::linux_dma::ScatterList;

use super::ffdhe;

const LINUX_EINVAL: i32 = 22;
const LINUX_ENOENT: i32 = 2;
const LINUX_ERR_PTR_RANGE: usize = 4095;
const CRYPTO_KPP_TFM_BASE: usize = 8;
const CRYPTO_ASYNC_REQUEST_SIZE: usize = 48;
const KPP_REQUEST_SRC_OFF: usize = CRYPTO_ASYNC_REQUEST_SIZE;
const KPP_REQUEST_DST_OFF: usize = KPP_REQUEST_SRC_OFF + size_of::<*mut ScatterList>();
const KPP_REQUEST_SRC_LEN_OFF: usize = KPP_REQUEST_DST_OFF + size_of::<*mut ScatterList>();
const KPP_REQUEST_DST_LEN_OFF: usize = KPP_REQUEST_SRC_LEN_OFF + size_of::<u32>();
const KPP_REQUEST_SIZE: usize = KPP_REQUEST_DST_LEN_OFF + size_of::<u32>();
const _: () = assert!(KPP_REQUEST_SIZE == 72);

#[repr(C)]
struct CryptoTfm {
    _refcnt: u32,
    _flags: u32,
    _node: i32,
    _pad: u32,
    _fb: *mut c_void,
    _exit: *mut c_void,
    alg: *const KppAlg,
}

#[repr(C)]
struct CryptoKpp {
    _reqsize: u32,
    _pad: u32,
    base: CryptoTfm,
    state: *mut KppState,
}

#[repr(C)]
struct KppAlg {
    set_secret: unsafe extern "C" fn(*mut CryptoKpp, *const c_void, u32) -> i32,
    generate_public: unsafe extern "C" fn(*mut u8) -> i32,
    compute_shared: unsafe extern "C" fn(*mut u8) -> i32,
    max_size: unsafe extern "C" fn(*mut CryptoKpp) -> u32,
}

struct KppState {
    prime: Mpi,
    width: usize,
    private_bits: usize,
    private: Option<Mpi>,
}

static KPP_ALG: KppAlg = KppAlg {
    set_secret: kpp_set_secret,
    generate_public: kpp_generate_public,
    compute_shared: kpp_compute_shared,
    max_size: kpp_max_size,
};

/// Register generic KPP transform allocation and destruction symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("crypto_alloc_kpp", crypto_alloc_kpp as *const () as usize, true);
    export("crypto_destroy_tfm", crypto_destroy_tfm as *const () as usize, true);
}

extern "C" fn crypto_alloc_kpp(name: *const u8, _ty: u32, _mask: u32) -> *mut CryptoKpp {
    let Some(name) = c_name(name) else { return err_ptr(LINUX_ENOENT); };
    let Some(group) = ffdhe::by_name(name) else { return err_ptr(LINUX_ENOENT); };
    let state = Box::new(KppState {
        prime: Mpi::from_be_bytes(group.prime), width: group.prime.len(), private_bits: group.private_bits, private: None,
    });
    Box::into_raw(Box::new(CryptoKpp {
        _reqsize: 0, _pad: 0,
        base: CryptoTfm { _refcnt: 1, _flags: 0, _node: -1, _pad: 0, _fb: ptr::null_mut(), _exit: ptr::null_mut(), alg: &KPP_ALG },
        state: Box::into_raw(state),
    }))
}

extern "C" fn crypto_destroy_tfm(mem: *mut u8, tfm: *mut CryptoTfm) {
    if mem.is_null() || is_err(mem) { return; }
    let kpp_base = mem.wrapping_add(CRYPTO_KPP_TFM_BASE).cast::<CryptoTfm>();
    if tfm == kpp_base {
        // SAFETY: the matched base offset proves mem is the CryptoKpp allocation from crypto_alloc_kpp.
        unsafe { let kpp = Box::from_raw(mem.cast::<CryptoKpp>()); drop(Box::from_raw(kpp.state)); }
        return;
    }
    super::shash::destroy_from_tfm(mem);
}

unsafe extern "C" fn kpp_set_secret(tfm: *mut CryptoKpp, secret: *const c_void, len: u32) -> i32 {
    if tfm.is_null() || !secret.is_null() || len != 0 { return -LINUX_EINVAL; }
    // SAFETY: tfm is owned by crypto_alloc_kpp and state is live until crypto_destroy_tfm.
    let state = unsafe { &mut *(*tfm).state };
    let bytes = state.private_bits.div_ceil(8);
    let mut raw = alloc::vec![0u8; bytes];
    devfs::misc::random_fill(&mut raw);
    raw[0] &= 0x7f;
    if raw.iter().all(|v| *v == 0) { *raw.last_mut().expect("private KPP key has nonzero width") = 1; }
    state.private = Some(Mpi::from_be_bytes(&raw));
    raw.fill(0);
    0
}

unsafe extern "C" fn kpp_generate_public(req: *mut u8) -> i32 {
    // SAFETY: the KPP callback receives a standard initialized KPP request.
    unsafe { kpp_compute(req, false) }
}
unsafe extern "C" fn kpp_compute_shared(req: *mut u8) -> i32 {
    // SAFETY: the KPP callback receives a standard initialized KPP request.
    unsafe { kpp_compute(req, true) }
}

unsafe extern "C" fn kpp_max_size(tfm: *mut CryptoKpp) -> u32 {
    if tfm.is_null() { return 0; }
    // SAFETY: tfm is an allocated transform whose state remains valid while the transform is live.
    unsafe { (*(*tfm).state).width as u32 }
}

unsafe fn kpp_compute(req: *mut u8, peer: bool) -> i32 {
    if req.is_null() { return -LINUX_EINVAL; }
    // SAFETY: req is non-null (checked above) and offset 24 is crypto_async_request's tfm field, the fixed ABI position the request() test helper writes and this shim relies on.
    let tfm = unsafe { ptr::read_unaligned(req.add(24).cast::<*mut CryptoTfm>()) };
    if tfm.is_null() { return -LINUX_EINVAL; }
    // SAFETY: tfm is non-null (checked above) and CRYPTO_KPP_TFM_BASE is CryptoKpp::base's offset (asserted in tests), so subtracting it recovers the enclosing CryptoKpp this callback fires on.
    let kpp = unsafe { (tfm.cast::<u8>().sub(CRYPTO_KPP_TFM_BASE)).cast::<CryptoKpp>() };
    // SAFETY: kpp is the CryptoKpp recovered above; its state field was set by crypto_alloc_kpp's Box::into_raw and stays live until crypto_destroy_tfm runs.
    let state = unsafe { &mut *(*kpp).state };
    let Some(private) = state.private.as_ref() else { return -LINUX_EINVAL; };
    // SAFETY: req was null-checked above and KPP_REQUEST_DST_OFF is the kpp_request dst-scatterlist field offset fixed by the KPP_REQUEST_SIZE layout assert.
    let dst = unsafe { ptr::read_unaligned(req.add(KPP_REQUEST_DST_OFF).cast::<*mut ScatterList>()) };
    // SAFETY: same req; dst_len is the u32 field immediately following dst in the fixed request layout.
    let dst_len = unsafe { ptr::read_unaligned(req.add(KPP_REQUEST_DST_LEN_OFF).cast::<u32>()) as usize };
    // SAFETY: writes back the required length into the same fixed DST_LEN_OFF slot on the caller's own request, matching Linux's report-required-size convention.
    if dst.is_null() || dst_len < state.width { unsafe { ptr::write_unaligned(req.add(KPP_REQUEST_DST_LEN_OFF).cast::<u32>(), state.width as u32); } return -LINUX_EINVAL; }
    let base = if peer {
        // SAFETY: src is read from the fixed KPP_REQUEST_SRC_OFF slot of the same null-checked req used for dst above.
        let src = unsafe { ptr::read_unaligned(req.add(KPP_REQUEST_SRC_OFF).cast::<*mut ScatterList>()) };
        // SAFETY: src_len sits at KPP_REQUEST_SRC_LEN_OFF, the field after src, within the same null-checked req allocation.
        let src_len = unsafe { ptr::read_unaligned(req.add(KPP_REQUEST_SRC_LEN_OFF).cast::<u32>()) as usize };
        if src.is_null() { return -LINUX_EINVAL; }
        // SAFETY: src is non-null (checked above) and points at a scatterlist entry whose dma_address/length the KPP caller set up to cover exactly src_len bytes, per the single-entry scatterlist convention this shim assumes.
        let data = unsafe { core::slice::from_raw_parts((*src).dma_address as *const u8, src_len) };
        let value = Mpi::from_be_bytes(data);
        if value <= Mpi::from_u64(1) || value >= state.prime { return -LINUX_EINVAL; }
        value
    } else { Mpi::from_u64(2) };
    let Some(value) = base.powm(private, &state.prime) else { return -LINUX_EINVAL; };
    let Some(bytes) = value.to_be_bytes(state.width) else { return -LINUX_EINVAL; };
    // SAFETY: dst is a one-entry scatterlist initialized by the in-kernel KPP caller.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), (*dst).dma_address as *mut u8, state.width); }
    0
}

fn c_name(name: *const u8) -> Option<&'static [u8]> {
    if name.is_null() { return None; }
    let mut n = 0usize;
    // SAFETY: name is null-checked above; this bounded 64-byte scan reads only the NUL-terminated prefix a caller's C string is required to have, and the returned slice borrows exactly the bytes already read.
    while n < 64 { if unsafe { *name.add(n) } == 0 { return Some(unsafe { core::slice::from_raw_parts(name, n) }); } n += 1; }
    None
}

fn err_ptr<T>(errno: i32) -> *mut T { (usize::MAX - errno as usize + 1) as *mut T }
fn is_err<T>(p: *mut T) -> bool { (p as usize) >= usize::MAX - LINUX_ERR_PTR_RANGE + 1 }

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct TestRequest { base: [u8; CRYPTO_ASYNC_REQUEST_SIZE], src: *mut ScatterList, dst: *mut ScatterList, src_len: u32, dst_len: u32 }

    fn request(tfm: *mut CryptoKpp, src: *mut ScatterList, dst: *mut ScatterList, src_len: u32, dst_len: u32) -> TestRequest {
        let mut request = TestRequest { base: [0; CRYPTO_ASYNC_REQUEST_SIZE], src, dst, src_len, dst_len };
        // SAFETY: tfm is always a CryptoKpp allocated by crypto_alloc_kpp in this test module, whose base field is live for the whole test body.
        let base = unsafe { &mut (*tfm).base as *mut CryptoTfm };
        request.base[24..24 + size_of::<usize>()].copy_from_slice(&(base as usize).to_ne_bytes());
        request
    }

    #[test]
    fn ffdhe_kpp_allocates_with_kernel_abi_offsets() {
        let _modules = crate::test_serial::claim();
        let tfm = crypto_alloc_kpp(c"ffdhe2048(dh)".as_ptr().cast(), 0, 0);
        assert!(!tfm.is_null() && !is_err(tfm));
        assert_eq!(core::mem::offset_of!(CryptoKpp, base), CRYPTO_KPP_TFM_BASE);
        assert_eq!(core::mem::offset_of!(CryptoTfm, alg), 32);
        // SAFETY: tfm was asserted non-null/non-error immediately above, satisfying kpp_max_size's live-allocation contract.
        assert_eq!(unsafe { kpp_max_size(tfm) }, 256);
        // SAFETY: same still-live tfm; this is its single destroy call, so the deref happens before the allocation is freed.
        crypto_destroy_tfm(tfm.cast(), unsafe { &mut (*tfm).base });
    }

    #[test]
    fn ffdhe_public_values_converge_on_one_shared_secret() {
        let _modules = crate::test_serial::claim();
        let a = crypto_alloc_kpp(c"ffdhe2048(dh)".as_ptr().cast(), 0, 0);
        let b = crypto_alloc_kpp(c"ffdhe2048(dh)".as_ptr().cast(), 0, 0);
        // SAFETY: a is a fresh crypto_alloc_kpp allocation for the always-resolvable "ffdhe2048(dh)" group, satisfying kpp_set_secret's non-null tfm contract.
        assert_eq!(unsafe { kpp_set_secret(a, ptr::null(), 0) }, 0);
        // SAFETY: b is likewise a fresh allocation for the same resolvable group as a, an independent tfm/state pair.
        assert_eq!(unsafe { kpp_set_secret(b, ptr::null(), 0) }, 0);
        let mut ap = [0u8; 256]; let mut bp = [0u8; 256];
        let mut asg = ScatterList { page_link: 0, offset: 0, length: 256, dma_address: ap.as_mut_ptr() as u64, dma_length: 0 };
        let mut bsg = ScatterList { page_link: 0, offset: 0, length: 256, dma_address: bp.as_mut_ptr() as u64, dma_length: 0 };
        let mut ar = request(a, ptr::null_mut(), &mut asg, 0, 256); let mut br = request(b, ptr::null_mut(), &mut bsg, 0, 256);
        // SAFETY: ar's TestRequest layout mirrors the real kpp_request field offsets asserted by the KPP_REQUEST_* consts, tfm slot filled by request() above.
        assert_eq!(unsafe { kpp_generate_public((&mut ar as *mut TestRequest).cast()) }, 0);
        // SAFETY: br mirrors the same TestRequest layout for tfm b, an independent allocation with its own dst scatterlist.
        assert_eq!(unsafe { kpp_generate_public((&mut br as *mut TestRequest).cast()) }, 0);
        let mut az = [0u8; 256]; let mut bz = [0u8; 256];
        let mut azsg = ScatterList { page_link: 0, offset: 0, length: 256, dma_address: az.as_mut_ptr() as u64, dma_length: 0 };
        let mut bzsg = ScatterList { page_link: 0, offset: 0, length: 256, dma_address: bz.as_mut_ptr() as u64, dma_length: 0 };
        let mut ap_sg = ScatterList { page_link: 0, offset: 0, length: 256, dma_address: ap.as_mut_ptr() as u64, dma_length: 0 };
        let mut bp_sg = ScatterList { page_link: 0, offset: 0, length: 256, dma_address: bp.as_mut_ptr() as u64, dma_length: 0 };
        let mut azr = request(a, &mut bp_sg, &mut azsg, 256, 256); let mut bzr = request(b, &mut ap_sg, &mut bzsg, 256, 256);
        // SAFETY: azr's src/dst scatterlists point at 256-byte stack buffers sized to match the ffdhe2048 state.width kpp_compute_shared reads/writes.
        assert_eq!(unsafe { kpp_compute_shared((&mut azr as *mut TestRequest).cast()) }, 0);
        // SAFETY: bzr mirrors azr for tfm b with its own 256-byte buffers, independent of a's allocation.
        assert_eq!(unsafe { kpp_compute_shared((&mut bzr as *mut TestRequest).cast()) }, 0);
        assert_eq!(az, bz);
        // SAFETY: a and b are still-live crypto_alloc_kpp allocations; this is each one's single destroy call, so both derefs precede the free.
        crypto_destroy_tfm(a.cast(), unsafe { &mut (*a).base }); crypto_destroy_tfm(b.cast(), unsafe { &mut (*b).base });
    }
}
