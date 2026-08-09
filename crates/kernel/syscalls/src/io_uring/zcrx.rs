// Zero-copy receive: an interface queue a ring registers, the area its
// payload lands in, and the refill queue userspace hands buffers back
// through.
//
// The shape is the reference's. One instance owns:
//   * an AREA — pages pinned out of the caller's own memory, split into
//     fixed-size buffers. The kernel never maps it anywhere new; the caller
//     already has it mapped, which is what makes a delivery zero-copy.
//   * a REFILL QUEUE — a kernel-allocated region the caller maps and writes
//     returned buffers into. It is refcounted RAM mapped as a
//     `VmaBacking::KernelFrame` (see `region.rs`), never a `PhysRange`: a
//     `PhysRange` mapping takes no reference, so closing the ring fd would
//     free a page the caller still maps.
//   * optionally a DEVICE RECEIVE QUEUE, bound through the netdev memory
//     provider so the device draws its receive buffers from the area.
//
// Two reference counts per buffer, and they are not the same count:
//   * the pool reference says the buffer is in flight somewhere in the
//     network stack. It reaching zero returns the buffer to the freelist.
//   * the USER reference says the caller has been told about the buffer and
//     has not handed it back. A refill entry drops one; only when it drops
//     the last user reference is the pool reference touched at all. Merging
//     them would let a caller return a buffer twice and receive into memory
//     the stack still owns.
//
// Module manifest:
//   area     — the pinned area, its buffer descriptors and its freelist
//   rq       — the refill queue over its region
//   ifq      — one instance: area + refill queue + device binding + notifications
//   provider — the memory-provider contract a bound device queue draws through
//   recv     — `IORING_OP_RECV_ZC`

#[path = "zcrx/area.rs"]     pub mod area;
#[path = "zcrx/rq.rs"]       pub mod rq;
#[path = "zcrx/ifq.rs"]      pub mod ifq;
#[path = "zcrx/provider.rs"] pub mod provider;
#[path = "zcrx/recv.rs"]     pub mod recv;

pub use area::ZcrxArea;
pub use ifq::{Binding, ZcrxIfq};
pub use rq::ZcrxRq;
