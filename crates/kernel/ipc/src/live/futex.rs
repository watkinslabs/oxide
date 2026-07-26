//! Module manifest:
//! - `core`: shared futex keys, waiter state, globals, and wake helpers.
//! - `wait`: single-futex wait/wake entrypoints.
//! - `waitv`: multi-futex wait entrypoints.
//! - `ops`: requeue/cmp_requeue/wake_op helpers.
//! - `robust`: robust-list exit cleanup.

mod core;
mod ops;
mod robust;
mod wait;
mod waitv;

pub use core::{FUTEX_PRIVATE_FLAG, FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK, FUTEX_BITSET_MATCH_ANY};
pub use ops::{cmp_requeue, requeue, wake_op};
pub use robust::exit_robust_list;
pub use wait::{dispatch, dispatch_timed};
pub use waitv::{dispatch_waitv, dispatch_waitv_timed};
