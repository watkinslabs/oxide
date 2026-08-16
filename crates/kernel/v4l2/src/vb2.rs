//! The buffer queue every streaming V4L2 device runs on.
//!
//! Module manifest:
//! - `state`: buffer states and the transitions the queue admits.
//! - `queue`: the queue and buffer structures, and the plane allocator.
//! - `reqbufs`: allocating, growing, removing and freeing buffers.
//! - `qbuf`: `PREPARE_BUF`, `QBUF`, `DQBUF`, `QUERYBUF`.
//! - `stream`: `STREAMON`, `STREAMOFF`, cancellation and driver completion.
//! - `poll`: readiness for `poll`/`select`/`epoll`.
//!
//! Nothing here locks or sleeps. The blocking half of `DQBUF` belongs to the
//! device node, which owns the wait queue; this subtree only decides whether a
//! caller may proceed, which is why every rule in it is testable without a
//! kernel.

pub mod state;
pub mod queue;
pub mod reqbufs;
pub mod qbuf;
pub mod stream;
pub mod poll;

pub use state::BufState;
pub use queue::{Buffer, Owner, Plane, PlaneAlloc, Queue, QueueSetup, MAX_BUFFERS};
pub use qbuf::{PlaneIn, QbufIn};
pub use stream::Completion;
