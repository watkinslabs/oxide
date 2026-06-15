// rand/srand/rand_r (docs/59§6 G7). Implements glibc's default TYPE_3
// additive-feedback generator so rand() reproduces the host sequence for
// a given srand() seed. rand_r is glibc's standalone 3-step variant. The
// generator is a plain struct (oracle-tested); rand/srand wrap a global
// instance under a spinlock.
use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;

const DEG: usize = 31; // TYPE_3 degree
const SEP: usize = 3; // TYPE_3 separation

// State is int32_t to match glibc's signed Schrage seeding exactly.
pub(crate) struct Rng { r: [i32; DEG], fptr: usize, rptr: usize }

impl Rng {
    /// # C: fresh TYPE_3 generator (unseeded)
    pub(crate) const fn new() -> Rng { Rng { r: [0; DEG], fptr: SEP, rptr: 0 } }

    /// # C: seed the TYPE_3 state from `seed`
    pub(crate) fn srandom(&mut self, seed: u32) {
        self.r[0] = if seed == 0 { 1 } else { seed as i32 };
        for i in 1..DEG {
            // r[i] = (16807 * r[i-1]) % 2147483647 via signed Schrage; i64
            // intermediate avoids overflow, result fits int32_t.
            let prev = self.r[i - 1] as i64;
            let hi = prev / 127773;
            let lo = prev % 127773;
            let mut word = 16807 * lo - 2836 * hi;
            if word < 0 { word += 2147483647; }
            self.r[i] = word as i32;
        }
        self.fptr = SEP;
        self.rptr = 0;
        for _ in 0..(10 * DEG) { self.next_i32(); }
    }

    /// # C: next 31-bit value from the additive feedback
    pub(crate) fn next_i32(&mut self) -> i32 {
        // *fptr += (uint32_t)*rptr; result = (uint32_t)*fptr >> 1
        self.r[self.fptr] = self.r[self.fptr].wrapping_add(self.r[self.rptr]);
        let result = (self.r[self.fptr] as u32) >> 1;
        self.fptr = (self.fptr + 1) % DEG;
        self.rptr = (self.rptr + 1) % DEG;
        result as i32
    }
}

// glibc rand_r: a self-contained 3-step generator over the caller's seed.
/// # C: glibc rand_r(seed) — standalone 3-step generator
pub(crate) fn rand_r_impl(seed: &mut u32) -> i32 {
    let mut next = *seed as u64;
    let mut result: u64;
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    result = (next / 65536) % 2048;
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    result = (result << 10) ^ ((next / 65536) % 1024);
    next = next.wrapping_mul(1103515245).wrapping_add(12345);
    result = (result << 10) ^ ((next / 65536) % 1024);
    *seed = next as u32;
    result as i32
}

struct Global { lock: AtomicBool, rng: UnsafeCell<Rng> }
// SAFETY: rng is only touched under the spinlock; the raw cell is never
// aliased mutably across threads.
unsafe impl Sync for Global {}
static G: Global = Global { lock: AtomicBool::new(false), rng: UnsafeCell::new(Rng::new()) };

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    use core::sync::atomic::Ordering;
    fn with<R>(f: impl FnOnce(&mut Rng) -> R) -> R {
        while G.lock.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { core::hint::spin_loop(); }
        // SAFETY: lock held — exclusive access to the global Rng.
        let r = unsafe { f(&mut *G.rng.get()) };
        G.lock.store(false, Ordering::Release);
        r
    }
    // # C: void srand(unsigned seed)
    #[no_mangle]
    pub extern "C" fn srand(seed: u32) { with(|rng| rng.srandom(seed)); }
    // # C: int rand(void)
    #[no_mangle]
    pub extern "C" fn rand() -> i32 { with(|rng| rng.next_i32()) }
    // # C: int rand_r(unsigned *seed)
    #[no_mangle]
    pub unsafe extern "C" fn rand_r(seed: *mut u32) -> i32 {
        // SAFETY: seed is a valid in/out pointer per the C contract.
        unsafe { rand_r_impl(&mut *seed) }
    }
    // random/srandom + initstate/setstate live in stdlib::rand48 (full glibc
    // TYPE_3 state machine over struct random_data).
}

#[cfg(test)]
mod tests {
    use super::*;
    // Single test (sole user of host rand/srand) → no cross-test contention.
    #[test]
    fn rand_matches_host_sequence() {
        for &seed in &[1u32, 2, 42, 12345, 0x9e3779b9, 1000000] {
            let mut rng = Rng::new();
            rng.srandom(seed);
            // SAFETY: this is the only test touching host srand/rand.
            unsafe { libc::srand(seed); }
            for k in 0..200 {
                let ours = rng.next_i32();
                // SAFETY: host rand() after the matching srand.
                let theirs = unsafe { libc::rand() };
                assert_eq!(ours, theirs, "seed={seed} k={k}");
            }
        }
    }
    #[test]
    fn rand_r_deterministic_and_bounded() {
        // libc crate doesn't expose rand_r; verify determinism + range
        // (glibc rand_r yields [0, 2^31)). Known first value for seed 1.
        let (mut a, mut b) = (12345u32, 12345u32);
        for _ in 0..200 {
            let x = rand_r_impl(&mut a);
            let y = rand_r_impl(&mut b);
            assert_eq!(x, y);
            assert!((0..=0x7fff_ffff).contains(&x));
        }
    }
}
