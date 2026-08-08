// The asynchronous execution engine — module manifest.
//
// An operation that cannot finish inside the submission that issued it has to
// run somewhere else, on a thread that can block. That thread must see exactly
// what the submitting task sees, or the operation it runs is not the operation
// that was asked for: the same address space (a buffer address means nothing
// otherwise), the same descriptor table (a descriptor number means nothing
// otherwise) and the same credentials (a permission check would be answered
// against the wrong identity). Borrowing those three for the length of one
// request is what `owner` does, and it is the whole reason a worker may run
// userspace's work at all.
//
// Module manifest:
//   owner  — the borrowed address space, descriptor table and credentials
//   pool   — the worker pool: the queue, the limits, the affinity, the clock
//   worker — one worker thread's loop
//   run    — issuing one request and continuing its chain

#[path = "iowq/owner.rs"]  pub mod owner;
#[path = "iowq/pool.rs"]   pub mod pool;
#[path = "iowq/worker.rs"] pub mod worker;
#[path = "iowq/run.rs"]    pub mod run;

pub use owner::Owner;
pub use pool::{acct, IoWq, WQ};
