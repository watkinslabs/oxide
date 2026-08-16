//! The two things a mounted volume does when nobody is asking it to.
//!
//! A log-structured filesystem cannot be only reactive. Space comes back only
//! when something moves the survivors out of a half-dead segment, and the
//! device only learns that space is free when something tells it — neither
//! happens on the write path, because both of them are slow and neither is
//! what the writer asked for. So each is a thread, each sleeps on an interval
//! that adapts to what it finds, and each yields to a volume that is being
//! used.
//!
//! Module manifest:
//! - `gc`:      the cleaner's policy — modes, the sleep walk, one wake's
//!              decision.
//! - `discard`: the discard policy, the pending runs, and one round's issue.
//! - `balance`: what an operation that used space does before it returns.
//! - `state`:   the knobs and wake points one mount's threads share.
//! - `waits`:   parking, chosen by whether there is a scheduler to park on.
//! - `round`:   one pass of each thread, over a real mount and no scheduler.
//! - `run`:     the threads themselves: spawn, loop, stop.
//! - `mount`:   the surface the rest of the filesystem calls.
//! - `knobs`:   the writable attributes, and what each will accept.

pub mod gc;
pub mod discard;
pub mod balance;
pub mod state;
pub mod round;
pub mod mount;
pub mod knobs;

#[cfg(target_os = "oxide-kernel")]
#[path = "bg/waits/kernel.rs"]
pub mod waits;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "bg/waits/hosted.rs"]
pub mod waits;

#[cfg(target_os = "oxide-kernel")]
#[path = "bg/run/kernel.rs"]
pub mod run;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "bg/run/hosted.rs"]
pub mod run;

pub use balance::{needs_checkpoint, BalanceFs, BgState};
pub use discard::{DiscardControl, DiscardPolicy, DiscardType, IoAware};
pub use gc::{GcKthread, GcMode, GcStep};
pub use round::{discard_pass, drain_discards, gc_pass};
pub use state::Bg;
