// Entropy source for temp names — glibc sysdeps/posix/tempname.c
// `random_bits()`: getrandom(2) with GRND_NONBLOCK is the primary source, and
// a clock/pid mix is the fallback for kernels that cannot answer (ENOSYS on
// pre-3.17, EAGAIN before the CSPRNG is seeded). This kernel implements
// getrandom, so the fallback is unreachable in practice.
//
// getrandom(2) contract (linux-master drivers/char/random.c,
// SYSCALL_DEFINE3(getrandom)): rejects unknown flags with EINVAL, returns
// EAGAIN under GRND_NONBLOCK when the CSPRNG is not yet ready, and
// get_random_bytes_user() returns the SHORT count already copied when a signal
// arrives mid-copy — so one call is not guaranteed to fill the buffer and the
// draw loops until it has RANDOM_VALUE_BYTES.
#![cfg(feature = "freestanding")]
use super::value::{mix_random_values, RANDOM_VALUE_BYTES};
use crate::internal::errno::__errno_location;
use crate::posix::io::getpid;
use crate::posix::random::{getrandom, GRND_NONBLOCK};
use crate::time::clock::{clock_gettime, timespec, CLOCK_MONOTONIC, CLOCK_REALTIME};
use core::sync::atomic::{AtomicU64, Ordering};

const EINTR: i32 = 4;
// Bounded resume budget for a signal-truncated draw; 8 bytes needs at most a
// couple of resumes, and a bound keeps a misbehaving kernel from spinning.
const DRAW_RETRIES: u32 = 8;
// Ersatz-path sequence: two fallback draws in one process differ even if both
// clocks read identically.
static SEQ: AtomicU64 = AtomicU64::new(0);

// Fill one random_value's worth of kernel entropy. True only on a full draw.
fn draw(out: &mut [u8; RANDOM_VALUE_BYTES]) -> bool {
    let mut done = 0usize;
    for _ in 0..DRAW_RETRIES {
        if done == RANDOM_VALUE_BYTES { return true; }
        // SAFETY: getrandom(2) writes at most RANDOM_VALUE_BYTES-done bytes at
        // out+done, which stays inside the fixed-size local array `out`.
        let n = unsafe { getrandom(out.as_mut_ptr().add(done), RANDOM_VALUE_BYTES - done, GRND_NONBLOCK) };
        if n > 0 { done += n as usize; continue; }
        // SAFETY: __errno_location returns this thread's live errno slot (TCB
        // or the pre-TCB fallback cell); reading it is the libc errno contract.
        let e = unsafe { *__errno_location() };
        if n < 0 && e == EINTR { continue; }
        return false; // ENOSYS / EAGAIN / EINVAL → ersatz entropy
    }
    done == RANDOM_VALUE_BYTES
}

// glibc `random_bits(&v, s)`: ersatz value derived from the previous value,
// both clocks, the pid, and a process sequence. Deliberately NOT seeded from
// any address (glibc: do not leak ASLR into a name that is typically public).
fn ersatz(prev: u64) -> u64 {
    let mut v = mix_random_values(prev, SEQ.fetch_add(1, Ordering::Relaxed));
    let mut rt = timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime(2) writes the local timespec out-param `rt`, which
    // is a live, correctly sized stack object for the whole call.
    unsafe { clock_gettime(CLOCK_REALTIME, &mut rt); }
    v = mix_random_values(v, rt.tv_sec as u64);
    v = mix_random_values(v, rt.tv_nsec as u64);
    let mut mono = timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime(2) writes the local timespec out-param `mono`,
    // which is a live, correctly sized stack object for the whole call.
    unsafe { clock_gettime(CLOCK_MONOTONIC, &mut mono); }
    v = mix_random_values(v, mono.tv_sec as u64);
    v = mix_random_values(v, mono.tv_nsec as u64);
    // SAFETY: getpid(2) takes no arguments, cannot fail, and touches no memory.
    mix_random_values(v, unsafe { getpid() } as u32 as u64)
}

/// # C: random_bits(&v, prev) → (v, high_quality)
pub fn random_bits(prev: u64) -> (u64, bool) {
    let mut b = [0u8; RANDOM_VALUE_BYTES];
    if draw(&mut b) { return (u64::from_le_bytes(b), true); }
    (ersatz(prev), false)
}
