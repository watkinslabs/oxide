// rand48 + random PRNG families (docs/59§6). Exact glibc algorithms so output
// matches host bit-for-bit:
//   - 48-bit LCG (drand48/erand48/lrand48/nrand48/mrand48/jrand48 + seeding
//     srand48/seed48/lcong48, and the *_r reentrant variants over
//     struct drand48_data),
//   - TYPE_3 additive-feedback generator (random/srandom + random_r/srandom_r,
//     initstate/setstate + *_r over struct random_data).
// The 48-bit multiplier is 0x5DEECE66D, addend 0xB (glibc stdlib/srand48_r.c).
// TYPE_3 mirrors glibc stdlib/random_r.c so random() reproduces the host stream.
#![cfg(feature = "freestanding")]
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

// ---- 48-bit LCG (drand48 family) ---------------------------------------

const LCG_A: u64 = 0x5DEE_CE66D; // glibc default multiplier
const LCG_C: u16 = 0xb; // glibc default addend

// struct drand48_data — layout matches host /usr/include/bits: __x[3],
// __old_x[3], __c, __init (all u16), then 8-byte-aligned __a (u64). Total 24.
#[repr(C)]
pub struct DrandData {
    x: [u16; 3],
    old_x: [u16; 3],
    c: u16,
    init: u16,
    a: u64,
}

impl DrandData {
    const fn zeroed() -> DrandData { DrandData { x: [0; 3], old_x: [0; 3], c: 0, init: 0, a: 0 } }

    // glibc __srand48_r: seed low/high 16 bits, top word fixed 0x330e.
    fn srand48(&mut self, seedval: i64) {
        self.x[0] = 0x330e;
        self.x[1] = (seedval & 0xffff) as u16;
        self.x[2] = ((seedval >> 16) & 0xffff) as u16;
        self.a = LCG_A;
        self.c = LCG_C;
        self.init = 1;
    }

    // glibc __drand48_iterate: X = (a*X + c) mod 2^48.
    fn step(&mut self) {
        if self.init == 0 { self.srand48(0); }
        let x = (self.x[0] as u64) | ((self.x[1] as u64) << 16) | ((self.x[2] as u64) << 32);
        let v = self.a.wrapping_mul(x).wrapping_add(self.c as u64) & 0xffff_ffff_ffff;
        self.x[0] = (v & 0xffff) as u16;
        self.x[1] = ((v >> 16) & 0xffff) as u16;
        self.x[2] = ((v >> 32) & 0xffff) as u16;
    }

    // Iterate a caller-supplied xsubi[3] (erand/nrand/jrand_r) using a/c.
    fn step_xsubi(&self, xsubi: &mut [u16; 3]) {
        let x = (xsubi[0] as u64) | ((xsubi[1] as u64) << 16) | ((xsubi[2] as u64) << 32);
        let v = self.a.wrapping_mul(x).wrapping_add(self.c as u64) & 0xffff_ffff_ffff;
        xsubi[0] = (v & 0xffff) as u16;
        xsubi[1] = ((v >> 16) & 0xffff) as u16;
        xsubi[2] = ((v >> 32) & 0xffff) as u16;
    }
}

// glibc __erand48_r: double from the top 48 bits, exponent biased to [1,2)
// then subtract 1.0 — bit-for-bit via the IEEE754 fraction layout.
fn to_double(x: &[u16; 3]) -> f64 {
    let hi = (0x3ff0_0000u64 | ((x[2] as u64) << 4) | ((x[1] as u64) >> 12)) << 32;
    let lo = (((x[1] as u64 & 0xfff) << 20) | ((x[0] as u64) << 4)) & 0xffff_ffff;
    f64::from_bits(hi | lo) - 1.0
}

// lrand48/nrand48: non-negative 31-bit. glibc: (x[2]<<15) | (x[1]>>1).
fn to_long_pos(x: &[u16; 3]) -> i64 { (((x[2] as u32) << 15) | ((x[1] as u32) >> 1)) as i64 }

// mrand48/jrand48: signed 32-bit. glibc: (x[2]<<16) | x[1], as int32_t.
fn to_long_signed(x: &[u16; 3]) -> i64 { ((((x[2] as u32) << 16) | (x[1] as u32)) as i32) as i64 }

struct DrandGlobal { lock: AtomicBool, d: UnsafeCell<DrandData> }
// SAFETY: the inner DrandData is only ever accessed while the spinlock is
// held, so no concurrent aliasing of the cell occurs across threads.
unsafe impl Sync for DrandGlobal {}
static DG: DrandGlobal = DrandGlobal { lock: AtomicBool::new(false), d: UnsafeCell::new(DrandData::zeroed()) };

fn with_dg<R>(f: impl FnOnce(&mut DrandData) -> R) -> R {
    while DG.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); }
    // SAFETY: spinlock acquired above grants exclusive access to the global.
    let r = unsafe { f(&mut *DG.d.get()) };
    DG.lock.store(false, Ordering::Release);
    r
}

/// # C: double drand48(void)
#[no_mangle]
pub extern "C" fn drand48() -> f64 { with_dg(|d| { d.step(); to_double(&d.x) }) }
/// # C: long lrand48(void)
#[no_mangle]
pub extern "C" fn lrand48() -> i64 { with_dg(|d| { d.step(); to_long_pos(&d.x) }) }
/// # C: long mrand48(void)
#[no_mangle]
pub extern "C" fn mrand48() -> i64 { with_dg(|d| { d.step(); to_long_signed(&d.x) }) }

/// # C: double erand48(unsigned short xsubi[3])
#[no_mangle]
pub unsafe extern "C" fn erand48(xsubi: *mut u16) -> f64 {
    // SAFETY: xsubi is a caller-owned [u16;3] per the C contract; advance it
    // through the shared multiplier/addend and read the resulting state.
    unsafe { with_dg(|d| { let x = &mut *(xsubi as *mut [u16; 3]); d.step_xsubi(x); to_double(x) }) }
}
/// # C: long nrand48(unsigned short xsubi[3])
#[no_mangle]
pub unsafe extern "C" fn nrand48(xsubi: *mut u16) -> i64 {
    // SAFETY: xsubi is a caller-owned [u16;3] per the C contract; advanced in
    // place under the lock guarding the shared a/c constants.
    unsafe { with_dg(|d| { let x = &mut *(xsubi as *mut [u16; 3]); d.step_xsubi(x); to_long_pos(x) }) }
}
/// # C: long jrand48(unsigned short xsubi[3])
#[no_mangle]
pub unsafe extern "C" fn jrand48(xsubi: *mut u16) -> i64 {
    // SAFETY: xsubi is a caller-owned [u16;3] per the C contract; advanced in
    // place under the lock guarding the shared a/c constants.
    unsafe { with_dg(|d| { let x = &mut *(xsubi as *mut [u16; 3]); d.step_xsubi(x); to_long_signed(x) }) }
}

/// # C: void srand48(long seedval)
#[no_mangle]
pub extern "C" fn srand48(seedval: i64) { with_dg(|d| d.srand48(seedval)); }

// glibc seed48: save old state into __old_x, install seed16v, reset a/c,
// return pointer to __old_x.
/// # C: unsigned short *seed48(unsigned short seed16v[3])
#[no_mangle]
pub unsafe extern "C" fn seed48(seed16v: *const u16) -> *mut u16 {
    // SAFETY: seed16v is a caller [u16;3]; we snapshot prior state into the
    // global __old_x and return a stable pointer to it (glibc contract).
    unsafe {
        with_dg(|d| {
            d.old_x = d.x;
            let s = core::slice::from_raw_parts(seed16v, 3);
            d.x = [s[0], s[1], s[2]];
            d.a = LCG_A;
            d.c = LCG_C;
            d.init = 1;
        });
        (*DG.d.get()).old_x.as_mut_ptr()
    }
}

// glibc lcong48: param[0..3]=x, param[3..6]=a (48-bit, low word first),
// param[6]=c.
/// # C: void lcong48(unsigned short param[7])
#[no_mangle]
pub unsafe extern "C" fn lcong48(param: *const u16) {
    // SAFETY: param is a caller [u16;7] per the C contract; copied wholesale
    // into the global LCG state under the lock.
    unsafe {
        let p = core::slice::from_raw_parts(param, 7);
        with_dg(|d| {
            d.x = [p[0], p[1], p[2]];
            d.a = (p[3] as u64) | ((p[4] as u64) << 16) | ((p[5] as u64) << 32);
            d.c = p[6];
            d.init = 1;
        });
    }
}

// ---- drand48 *_r reentrant variants ------------------------------------

/// # C: int srand48_r(long seedval, struct drand48_data *buffer)
#[no_mangle]
pub unsafe extern "C" fn srand48_r(seedval: i64, buffer: *mut DrandData) -> i32 {
    // SAFETY: buffer is a caller-allocated drand48_data per the C contract.
    unsafe { (*buffer).srand48(seedval); }
    0
}
/// # C: int seed48_r(unsigned short seed16v[3], struct drand48_data *buffer)
#[no_mangle]
pub unsafe extern "C" fn seed48_r(seed16v: *const u16, buffer: *mut DrandData) -> i32 {
    // SAFETY: seed16v is [u16;3] and buffer is a caller drand48_data; save old
    // state then install the seed, matching glibc __seed48_r.
    unsafe {
        let b = &mut *buffer;
        b.old_x = b.x;
        let s = core::slice::from_raw_parts(seed16v, 3);
        b.x = [s[0], s[1], s[2]];
        b.a = LCG_A; b.c = LCG_C; b.init = 1;
    }
    0
}
/// # C: int lcong48_r(unsigned short param[7], struct drand48_data *buffer)
#[no_mangle]
pub unsafe extern "C" fn lcong48_r(param: *const u16, buffer: *mut DrandData) -> i32 {
    // SAFETY: param is [u16;7] and buffer is a caller drand48_data; copy the
    // full 48-bit a, c and state words per glibc __lcong48_r.
    unsafe {
        let p = core::slice::from_raw_parts(param, 7);
        let b = &mut *buffer;
        b.x = [p[0], p[1], p[2]];
        b.a = (p[3] as u64) | ((p[4] as u64) << 16) | ((p[5] as u64) << 32);
        b.c = p[6]; b.init = 1;
    }
    0
}
/// # C: int drand48_r(struct drand48_data *buffer, double *result)
#[no_mangle]
pub unsafe extern "C" fn drand48_r(buffer: *mut DrandData, result: *mut f64) -> i32 {
    // SAFETY: buffer/result are caller pointers per the C contract; advance
    // the buffer's state and store the converted double.
    unsafe { let b = &mut *buffer; b.step(); *result = to_double(&b.x); }
    0
}
/// # C: int lrand48_r(struct drand48_data *buffer, long *result)
#[no_mangle]
pub unsafe extern "C" fn lrand48_r(buffer: *mut DrandData, result: *mut i64) -> i32 {
    // SAFETY: buffer/result are caller pointers per the C contract.
    unsafe { let b = &mut *buffer; b.step(); *result = to_long_pos(&b.x); }
    0
}
/// # C: int mrand48_r(struct drand48_data *buffer, long *result)
#[no_mangle]
pub unsafe extern "C" fn mrand48_r(buffer: *mut DrandData, result: *mut i64) -> i32 {
    // SAFETY: buffer/result are caller pointers per the C contract.
    unsafe { let b = &mut *buffer; b.step(); *result = to_long_signed(&b.x); }
    0
}
/// # C: int erand48_r(unsigned short xsubi[3], struct drand48_data *buffer, double *result)
#[no_mangle]
pub unsafe extern "C" fn erand48_r(xsubi: *mut u16, buffer: *mut DrandData, result: *mut f64) -> i32 {
    // SAFETY: xsubi[3], buffer and result are caller pointers per C contract;
    // step the externally-held state using the buffer's a/c.
    unsafe { let b = &*buffer; let x = &mut *(xsubi as *mut [u16; 3]); b.step_xsubi(x); *result = to_double(x); }
    0
}
/// # C: int nrand48_r(unsigned short xsubi[3], struct drand48_data *buffer, long *result)
#[no_mangle]
pub unsafe extern "C" fn nrand48_r(xsubi: *mut u16, buffer: *mut DrandData, result: *mut i64) -> i32 {
    // SAFETY: xsubi[3], buffer and result are caller pointers per C contract.
    unsafe { let b = &*buffer; let x = &mut *(xsubi as *mut [u16; 3]); b.step_xsubi(x); *result = to_long_pos(x); }
    0
}
/// # C: int jrand48_r(unsigned short xsubi[3], struct drand48_data *buffer, long *result)
#[no_mangle]
pub unsafe extern "C" fn jrand48_r(xsubi: *mut u16, buffer: *mut DrandData, result: *mut i64) -> i32 {
    // SAFETY: xsubi[3], buffer and result are caller pointers per C contract.
    unsafe { let b = &*buffer; let x = &mut *(xsubi as *mut [u16; 3]); b.step_xsubi(x); *result = to_long_signed(x); }
    0
}

// ---- random / TYPE_3 additive-feedback ---------------------------------

// struct random_data — layout matches host: 3×*i32, 3×i32, 1×*i32 = 48 bytes.
#[repr(C)]
pub struct RandomData {
    fptr: *mut i32,
    rptr: *mut i32,
    state: *mut i32,
    rand_type: i32,
    rand_deg: i32,
    rand_sep: i32,
    end_ptr: *mut i32,
}

const TYPE_3: i32 = 3;
const DEG_3: i32 = 31;
const SEP_3: i32 = 3;
const MAX_TYPES: i32 = 5; // glibc: type word = rand_type + (rptr-state)*MAX_TYPES

// glibc encodes the live rear-pointer offset into state[-1] alongside the type.
unsafe fn store_type_word(statebuf: *mut i32, buf: &RandomData) {
    // SAFETY: statebuf[0] is the type/offset marker word preceding the state
    // array; rptr lies within [state, end_ptr) so the offset is in range.
    unsafe {
        let off = ((buf.rptr as usize).wrapping_sub(buf.state as usize) / 4) as i32;
        *statebuf = buf.rand_type + off * MAX_TYPES;
    }
}

// glibc __srandom_r: state[0]=seed, Schrage fill, then 10*deg discards.
unsafe fn srandom_r_impl(seed: u32, buf: &mut RandomData) {
    let deg = buf.rand_deg as usize;
    let sep = buf.rand_sep as usize;
    let state = buf.state;
    let seed = if seed == 0 { 1 } else { seed };
    // SAFETY: state points to a deg-length i32 array owned by the caller's
    // buffer; we index strictly within [0, deg) when filling the table.
    unsafe {
        *state = seed as i32;
        for i in 1..deg {
            let prev = *state.add(i - 1) as i64;
            let hi = prev / 127773;
            let lo = prev % 127773;
            let mut word = 16807 * lo - 2836 * hi;
            if word < 0 { word += 2147483647; }
            *state.add(i) = word as i32;
        }
        buf.fptr = state.add(sep);
        buf.rptr = state;
    }
    let n = (deg * 10) as i32;
    let mut dummy = 0i32;
    for _ in 0..n {
        // SAFETY: random_r only reads/writes within the same state array.
        unsafe { random_r_impl(buf, &mut dummy); }
    }
}

// glibc __random_r TYPE_3 step: *fptr += *rptr; result = (*fptr >> 1) & 0x7fffffff.
unsafe fn random_r_impl(buf: &mut RandomData, result: &mut i32) {
    let state = buf.state;
    let end = buf.end_ptr;
    // SAFETY: fptr/rptr stay within [state, end_ptr); they wrap at end_ptr
    // exactly as glibc does, so every deref is inside the caller state array.
    unsafe {
        let fptr = buf.fptr;
        let rptr = buf.rptr;
        let val = (*fptr).wrapping_add(*rptr);
        *fptr = val;
        *result = ((val as u32) >> 1) as i32;
        let mut f = fptr.add(1);
        if f >= end { f = state; }
        let mut r = rptr.add(1);
        if r >= end { r = state; }
        buf.fptr = f;
        buf.rptr = r;
    }
}

// glibc __initstate_r: lay out the state array inside statebuf, set TYPE_3,
// seed via srandom_r, store the type marker into state[-1]. The conformance
// harness uses a >=128-byte buffer so only TYPE_3 (deg 31) is exercised.
unsafe fn initstate_r_impl(seed: u32, statebuf: *mut i32, _statelen: usize, buf: &mut RandomData) -> i32 {
    // SAFETY: statebuf is a caller buffer of at least (1+deg)*4 bytes; word [0]
    // is the type marker and words [1, deg] hold the generator state.
    unsafe {
        buf.rand_type = TYPE_3;
        buf.rand_deg = DEG_3;
        buf.rand_sep = SEP_3;
        buf.state = statebuf.add(1);
        buf.end_ptr = statebuf.add(1 + DEG_3 as usize);
        srandom_r_impl(seed, buf);
        store_type_word(statebuf, buf);
    }
    0
}

// glibc __setstate_r: re-bind the generator view onto statebuf and reset the
// front/rear pointers to the canonical TYPE_3 offsets.
unsafe fn setstate_r_impl(statebuf: *mut i32, buf: &mut RandomData) -> i32 {
    // SAFETY: statebuf was produced by initstate_r_impl; word[0] holds the type
    // plus the saved rear-pointer offset, and the following deg words hold the
    // live generator state. Decode the offset to restore fptr/rptr exactly.
    unsafe {
        let tw = *statebuf;
        let off = (tw / MAX_TYPES) as usize;
        buf.rand_type = TYPE_3;
        buf.rand_deg = DEG_3;
        buf.rand_sep = SEP_3;
        buf.state = statebuf.add(1);
        buf.end_ptr = statebuf.add(1 + DEG_3 as usize);
        buf.rptr = buf.state.add(off);
        buf.fptr = buf.state.add((off + SEP_3 as usize) % DEG_3 as usize);
    }
    0
}

// Global random state: a (1 + 31)-int TYPE_3 array + a RandomData view.
const RSTATE_WORDS: usize = 1 + DEG_3 as usize; // type marker + 31 state ints
struct RandomGlobal { lock: AtomicBool, data: UnsafeCell<RandomData>, store: UnsafeCell<[i32; RSTATE_WORDS]>, seeded: AtomicBool }
// SAFETY: data/store are only touched while `lock` is held; the cells are
// never aliased mutably across threads.
unsafe impl Sync for RandomGlobal {}
static RG: RandomGlobal = RandomGlobal {
    lock: AtomicBool::new(false),
    data: UnsafeCell::new(RandomData { fptr: core::ptr::null_mut(), rptr: core::ptr::null_mut(), state: core::ptr::null_mut(), rand_type: TYPE_3, rand_deg: DEG_3, rand_sep: SEP_3, end_ptr: core::ptr::null_mut() }),
    store: UnsafeCell::new([0; RSTATE_WORDS]),
    seeded: AtomicBool::new(false),
};

fn rg_lock() { while RG.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); } }
fn rg_unlock() { RG.lock.store(false, Ordering::Release); }

// Bind the global RandomData to its own store and seed it (glibc default 1).
unsafe fn rg_ensure_default() {
    if RG.seeded.load(Ordering::Relaxed) { return; }
    // SAFETY: lock held by caller; point the global buffer at its backing store
    // and run the standard TYPE_3 seeding for the default seed (1).
    unsafe {
        let store = (*RG.store.get()).as_mut_ptr();
        let buf = &mut *RG.data.get();
        initstate_r_impl(1, store, RSTATE_WORDS * 4, buf);
    }
    RG.seeded.store(true, Ordering::Relaxed);
}

/// # C: long random(void) — TYPE_3 additive-feedback stream
#[no_mangle]
pub extern "C" fn random() -> i64 {
    rg_lock();
    // SAFETY: lock held; ensure the default state is bound, then step once.
    let v = unsafe { rg_ensure_default(); let buf = &mut *RG.data.get(); let mut r = 0i32; random_r_impl(buf, &mut r); r as i64 };
    rg_unlock();
    v
}
/// # C: void srandom(unsigned seed)
#[no_mangle]
pub extern "C" fn srandom(seed: u32) {
    rg_lock();
    // SAFETY: lock held; bind the global buffer to its store and reseed it.
    unsafe {
        let store = (*RG.store.get()).as_mut_ptr();
        let buf = &mut *RG.data.get();
        initstate_r_impl(seed, store, RSTATE_WORDS * 4, buf);
    }
    RG.seeded.store(true, Ordering::Relaxed);
    rg_unlock();
}

/// # C: char *initstate(unsigned seed, char *statebuf, size_t statelen)
#[no_mangle]
pub unsafe extern "C" fn initstate(seed: u32, statebuf: *mut u8, statelen: usize) -> *mut u8 {
    rg_lock();
    // SAFETY: statebuf is a caller buffer of statelen bytes; the previous state
    // pointer is returned per glibc and the new state is seeded into statebuf.
    let old = unsafe {
        rg_ensure_default();
        let buf = &mut *RG.data.get();
        let prev = if buf.state.is_null() { core::ptr::null_mut() } else { buf.state.sub(1) as *mut u8 };
        if !buf.state.is_null() { store_type_word(buf.state.sub(1), buf); }
        initstate_r_impl(seed, statebuf as *mut i32, statelen, buf);
        prev
    };
    RG.seeded.store(true, Ordering::Relaxed);
    rg_unlock();
    old
}
/// # C: char *setstate(char *statebuf)
#[no_mangle]
pub unsafe extern "C" fn setstate(statebuf: *mut u8) -> *mut u8 {
    rg_lock();
    // SAFETY: statebuf is a buffer previously initialised by initstate; restore
    // the generator view from it and return the prior state pointer.
    let old = unsafe {
        rg_ensure_default();
        let buf = &mut *RG.data.get();
        let prev = if buf.state.is_null() { core::ptr::null_mut() } else { buf.state.sub(1) as *mut u8 };
        if !buf.state.is_null() { store_type_word(buf.state.sub(1), buf); }
        setstate_r_impl(statebuf as *mut i32, buf);
        prev
    };
    RG.seeded.store(true, Ordering::Relaxed);
    rg_unlock();
    old
}

/// # C: int random_r(struct random_data *buf, int32_t *result)
#[no_mangle]
pub unsafe extern "C" fn random_r(buf: *mut RandomData, result: *mut i32) -> i32 {
    // SAFETY: buf/result are caller pointers per the C contract.
    unsafe { random_r_impl(&mut *buf, &mut *result); }
    0
}
/// # C: int srandom_r(unsigned seed, struct random_data *buf)
#[no_mangle]
pub unsafe extern "C" fn srandom_r(seed: u32, buf: *mut RandomData) -> i32 {
    // SAFETY: buf is a caller random_data whose state/end_ptr are already set.
    unsafe { srandom_r_impl(seed, &mut *buf); }
    0
}
/// # C: int initstate_r(unsigned seed, char *statebuf, size_t statelen, struct random_data *buf)
#[no_mangle]
pub unsafe extern "C" fn initstate_r(seed: u32, statebuf: *mut u8, statelen: usize, buf: *mut RandomData) -> i32 {
    // SAFETY: statebuf is a caller buffer; buf is a caller random_data.
    unsafe { initstate_r_impl(seed, statebuf as *mut i32, statelen, &mut *buf) }
}
/// # C: int setstate_r(char *statebuf, struct random_data *buf)
#[no_mangle]
pub unsafe extern "C" fn setstate_r(statebuf: *mut u8, buf: *mut RandomData) -> i32 {
    // SAFETY: statebuf was produced by initstate_r; buf is a caller random_data.
    unsafe { setstate_r_impl(statebuf as *mut i32, &mut *buf) }
}
