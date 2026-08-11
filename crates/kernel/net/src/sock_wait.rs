// Socket sleep queue — the wait-queue head a socket sleeps on, the role
// `sk_sleep(sk)` fills for the reference stack. Every AF_UNIX/INET blocking
// path in this crate parks here and is roused from here.
//
// Contract (the reference's `prepare_to_wait_exclusive` → unlock →
// `schedule_timeout` → `finish_wait` sequence, e.g. the AF_UNIX stream
// connect backlog wait):
//
//   1. under the resource lock: `prepare_to_wait_interruptible_with_deadline(deadline)`
//      publishes the caller on this queue, so a waker that takes the resource
//      lock after this point cannot miss it;
//   2. drop the resource lock;
//   3. `wait()` yields until a wake lands or the deadline passes;
//   4. `remove_current()` retires the registration.
//
// Wakers call `wake_one` / `wake_all` AFTER dropping the resource lock.
//
// Module manifest:
//   - kernel: the live-scheduler realisation — task park on the scheduler's
//     wait list, yield through the one `schedule()` switch primitive.
//   - hosted: the host-thread realisation — per-waiter wake flags under the
//     queue lock, yielding until the flag is set or the deadline passes.
//
// Both are real implementations of the same queue selected by target; there is
// no second wait mechanism beside a production one, and no test-only path.

#[cfg(target_os = "oxide-kernel")]
mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub use kernel::SockWaitQueue;

#[cfg(not(target_os = "oxide-kernel"))]
mod hosted;
#[cfg(not(target_os = "oxide-kernel"))]
pub use hosted::SockWaitQueue;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests;
