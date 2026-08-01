// Re-includes the REAL production PI-futex source. A real on-disk directory so
// the `#[path]` includes below resolve — rustc joins the path against this
// module's own directory and opens it without resolving `..` through
// directories that do not exist.
#![allow(dead_code)]
#[path = "../../../src/live/futex/pi/state.rs"] pub mod state;
#[path = "../../../src/live/futex/pi/lock.rs"] pub mod lock;
#[path = "../../../src/live/futex/pi/park.rs"] pub mod park;
#[path = "../../../src/live/futex/pi/unlock.rs"] pub mod unlock;
#[path = "../../../src/live/futex/pi/exit.rs"] pub mod exit;
#[path = "../../../src/live/futex/pi/requeue.rs"] pub mod requeue;

pub use exit::exit_pi_state_list;
pub use lock::lock_pi;
#[allow(unused_imports)] pub use requeue::{cmp_requeue_pi, has_requeue_pi_waiter, wait_requeue_pi};
pub use unlock::unlock_pi;
