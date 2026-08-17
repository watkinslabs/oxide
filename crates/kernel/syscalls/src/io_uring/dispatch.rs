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
//   rw_vec   — a vectored transfer whose segments address a registered buffer
//   fs_ops   — path, descriptor and extended-attribute operations
//   splice_ops — moving bytes between two descriptions
//   proc_ops — waiting on a futex word or on a child
//   net_ops  — socket operations
//   net_send — one message gathered from several pieces (bundle, vector,
//              registered buffer)
//   net_recv — a receive whose bytes land somewhere other than the address
//              the entry names (drawn buffer, framed buffer, pinned buffer)
//   bundle_io — a send or receive spanning a RUN of provided buffers
//   ring_ops — operations on ring state itself
//   async_ops — operations on the ring's own in-flight work

#[path = "dispatch/outcome.rs"]  pub mod outcome;
#[path = "dispatch/fdres.rs"]    pub mod fdres;
#[path = "dispatch/router.rs"]   pub mod router;
#[path = "dispatch/rw.rs"]       pub mod rw;
#[path = "dispatch/rw_vec.rs"]   pub mod rw_vec;
#[path = "dispatch/fs_ops.rs"]   pub mod fs_ops;
#[path = "dispatch/splice_ops.rs"] pub mod splice_ops;
#[path = "dispatch/proc_ops.rs"] pub mod proc_ops;
#[path = "dispatch/net_ops.rs"]  pub mod net_ops;
#[path = "dispatch/net_send.rs"] pub mod net_send;
#[path = "dispatch/net_recv.rs"] pub mod net_recv;
#[path = "dispatch/bundle_io.rs"] pub mod bundle_io;
#[path = "dispatch/ring_ops.rs"] pub mod ring_ops;
#[path = "dispatch/async_ops.rs"] pub mod async_ops;

pub use outcome::OpOutcome;
pub use router::dispatch_op;
