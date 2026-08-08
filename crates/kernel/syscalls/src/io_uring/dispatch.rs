// `IORING_OP_*` execution — module manifest.
//
// Every operation runs synchronously in the submitting task, so each opcode
// maps onto the same work the corresponding syscall does, with the operands
// taken from the SQE's per-opcode unions.
//
// Module manifest:
//   outcome  — what one operation reports back to the submission engine
//   fdres    — fixed files, direct descriptors and provided-buffer selection
//   router   — opcode → handler
//   rw       — read/write family, fixed buffers, sync and size ops
//   fs_ops   — path, descriptor and extended-attribute operations
//   net_ops  — socket operations
//   ring_ops — operations on ring state itself
//   async_ops — operations on the ring's own in-flight work

#[path = "dispatch/outcome.rs"]  pub mod outcome;
#[path = "dispatch/fdres.rs"]    pub mod fdres;
#[path = "dispatch/router.rs"]   pub mod router;
#[path = "dispatch/rw.rs"]       pub mod rw;
#[path = "dispatch/fs_ops.rs"]   pub mod fs_ops;
#[path = "dispatch/net_ops.rs"]  pub mod net_ops;
#[path = "dispatch/ring_ops.rs"] pub mod ring_ops;
#[path = "dispatch/async_ops.rs"] pub mod async_ops;

pub use outcome::OpOutcome;
pub use router::dispatch_op;
