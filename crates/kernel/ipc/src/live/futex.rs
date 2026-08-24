//! Module manifest:
//! - `core`: shared futex keys, waiter state, globals, and wake helpers.
//! - `wait`: single-futex wait/wake entrypoints.
//! - `waitv`: multi-futex wait entrypoints.
//! - `ops`: requeue/cmp_requeue/wake_op helpers.
//! - `numa`: futex2 NUMA/mempolicy key preflight (node word read/write).
//! - `robust`: robust-list exit cleanup.

mod core;
mod numa;
mod ops;
mod pi;
mod robust;
mod wait;
mod waitv;

pub use core::{
    FUTEX_BITSET_MATCH_ANY, FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK, FUTEX_PRIVATE_FLAG,
    FUTEX_ROBUST_LIST32, FUTEX_ROBUST_UNLOCK,
};
pub use core::{callback_probe, register_callback, WaitCallback, WaitRegistration};
pub use numa::futex2_key_preflight;
pub use ops::{cmp_requeue, requeue, wake_op};
pub use pi::{cmp_requeue_pi, exit_pi_state_list, lock_pi, unlock_pi, wait_requeue_pi};
pub use robust::exit_robust_list;
pub use wait::{dispatch, dispatch_timed, dispatch_timed_pending};
pub use waitv::{WaitvEntry, dispatch_waitv_timed};
