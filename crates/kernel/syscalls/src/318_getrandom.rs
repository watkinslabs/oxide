// 318 getrandom — one syscall, one file (docs/53 §0).

use syscall::errno::Errno;
use syscall::getrandom::{cold_pool_action, validate_grnd_flags, wait_step, ColdPool,
    WaitOutcome, CRNG_WAIT_POLL_NS, GETRANDOM_COUNT_MAX};
use syscall::SyscallArgs;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// # C: O(1)
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

/// Linux `wait_for_random_bytes()` (`drivers/char/random.c`): loop until
/// `crng_ready()`, waking on a 1 s timeout so a pool that becomes ready with no
/// explicit wakeup still releases waiters, and returning `-ERESTARTSYS` when a
/// signal arrives first.
///
/// This used to be unreachable: `crng::reseed()` set the ready flag whether or
/// not any entropy source answered, so `is_initialized()` was true from the
/// first call and no caller ever waited. With the flag now honest, a boot with
/// no RDRAND/RNDR and no virtio-rng really does park here — which is the Linux
/// behaviour userspace expects when it asks for secure bytes.
/// # C: O(schedules until seeded or signal)
fn wait_for_random_bytes(cur: &sched::Task) -> WaitOutcome {
    use sched::SleepWake;
    loop {
        let pending = cur.sleep_wake() == SleepWake::Deliver;
        if let Some(out) = wait_step(crng::is_initialized(), pending) { return out; }
        // Linux calls `try_to_generate_entropy()` each pass; our equivalent is
        // re-polling every source, which also folds fresh cycle-counter jitter.
        if crng::reseed() { return WaitOutcome::Ready; }
        // SAFETY: process context; the current task is enqueued on a scheduler
        // wait list with an absolute wake deadline, then immediately scheduled.
        unsafe {
            CRNG_WAIT.park_with_deadline(monotonic_ns().saturating_add(CRNG_WAIT_POLL_NS));
            sched::live::park_yield();
        }
    }
}

/// Linux `crng_init_wait` — the queue a newly-credited entropy source releases;
/// the 1 s poll deadline covers the case where the credit lands with no wakeup.
static CRNG_WAIT: sched::live::WaitList = sched::live::WaitList::new();

/// # C: O(1)
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// `sys_getrandom(buf, len, flags)` — slot 318. Fills `buf` from the kernel
/// CSPRNG (`crng`: ChaCha20 with fast key erasure, seeded from virtio-rng /
/// RDRAND / RNDR plus cycle-counter jitter — Linux
/// `drivers/char/random.c`'s construction).
///
/// Flags per Linux `getrandom(2)`: unknown bits and `GRND_RANDOM|GRND_INSECURE`
/// together are `EINVAL` (`syscall::getrandom::validate_grnd_flags`).
/// `GRND_RANDOM` and `GRND_INSECURE` select the same generator, exactly as on
/// Linux since 5.6 — `/dev/random` and `/dev/urandom` were unified there and
/// `GRND_RANDOM` became a no-op.
///
/// Cold-pool behaviour now matches Linux exactly, because `crng` can finally
/// report a cold pool: `GRND_INSECURE` proceeds, `GRND_NONBLOCK` returns
/// `EAGAIN`, and everyone else blocks in `wait_for_random_bytes()` until a real
/// entropy source contributes (or a signal arrives, giving `ERESTARTSYS`).
/// # C: O(len), plus the cold-pool wait
pub fn sys_getrandom(args: &SyscallArgs) -> i64 {
    let buf = args.a0;
    // Linux clamps count to INT_MAX before touching the buffer (signed
    // ssize_t return); flags are the low 32 bits of the raw register arg.
    let len = args.a1.min(GETRANDOM_COUNT_MAX);
    let flags = args.a2 as u32;
    if let Err(e) = validate_grnd_flags(flags) { return err(e); }
    if len == 0 { return 0; }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, len, 1) { return rv; }
    if !crng::is_initialized() {
        // `GRND_INSECURE` skips the readiness gate outright, so don't even
        // reseed on its behalf; every other caller gets a seed attempt first.
        match cold_pool_action(flags) {
            ColdPool::Proceed => {}
            ColdPool::Again => {
                if !crng::reseed() { return err(Errno::Eagain); }
            }
            ColdPool::Wait => {
                if !crng::reseed() {
                    let Some(cur) = current_task() else { return err(Errno::Eagain) };
                    if wait_for_random_bytes(cur) == WaitOutcome::Restart {
                        return syscall::restart::restart_sys();
                    }
                }
            }
        }
    }
    // Chunked through a kernel buffer so the CSPRNG output never has to be
    // produced directly into a user page.
    const CHUNK: usize = 256;
    let mut scratch = [0u8; CHUNK];
    let mut written: u64 = 0;
    while written < len {
        let n = core::cmp::min(CHUNK as u64, len - written) as usize;
        crng::fill(&mut scratch[..n]);
        if uaccess::copy_to_user(buf + written, &scratch[..n]).is_err() {
            // Linux returns the short count when some bytes already landed.
            return if written > 0 { written as i64 } else { err(Errno::Efault) };
        }
        written += n as u64;
    }
    written as i64
}
