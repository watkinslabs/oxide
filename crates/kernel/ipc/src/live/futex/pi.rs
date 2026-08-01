//! Priority-inheritance futexes — `FUTEX_LOCK_PI`, `FUTEX_LOCK_PI2`,
//! `FUTEX_TRYLOCK_PI`, `FUTEX_UNLOCK_PI`, `FUTEX_WAIT_REQUEUE_PI`,
//! `FUTEX_CMP_REQUEUE_PI`.
//!
//! Module manifest:
//! - `state`: the PI-state table, waiter entries, grant slots, boost plumbing.
//! - `lock`: `futex_lock_pi` / trylock, owner attach, waiter unqueue.
//! - `park`: the block-until-granted loop and its wake classification.
//! - `unlock`: `futex_unlock_pi` and the ownership handoff.
//! - `exit`: `exit_pi_state_list` — owner-death handoff with FUTEX_OWNER_DIED.
//! - `requeue`: `FUTEX_WAIT_REQUEUE_PI` / `FUTEX_CMP_REQUEUE_PI`.
//!
//! The word transitions and their errnos live in the non-gated
//! `crate::futex_pi_rules`; the ordering rule for the boost lives in the
//! non-gated `sched::pi_prio`. Both are hosted-tested.

mod exit;
mod lock;
mod park;
mod requeue;
mod state;
mod unlock;

pub use exit::exit_pi_state_list;
pub use lock::lock_pi;
pub use requeue::{cmp_requeue_pi, has_requeue_pi_waiter, wait_requeue_pi};
pub use unlock::unlock_pi;
