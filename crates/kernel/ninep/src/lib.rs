// 9P — the network filesystem protocol a hypervisor uses to export a host
// directory into a guest, and the client that speaks it.
//
// Module manifest:
//   * `uapi`      — protocol constants: opcodes, masks, flags, limits.
//   * `err`       — the client error taxonomy and both dialects' errno mapping.
//   * `codec`     — the byte-faithful wire codec.
//   * `transport` — the seam a virtio queue or a byte stream plugs into.
//   * `client`    — tags, fids, RPC, flush, and the three dialects' operations.
//   * `opts`      — mount-option parsing.
//
// Nothing here is target-gated: the whole protocol and client are exercised
// hosted against a scripted server, and only the transports touch a device.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;

pub mod uapi;
pub mod err;
pub mod codec;
pub mod transport;
pub mod client;
pub mod opts;

pub use client::{Client, Fid, FidRef, Reply, Request};
pub use codec::{Dialect, Qid};
pub use err::{NpError, NpResult};
pub use opts::MountOpts;
pub use transport::{ReplySink, Transport, TransportRef};

/// `V9FS_MAGIC` — the `statfs` `f_type` a 9P mount reports. # C: O(1)
pub const V9FS_MAGIC: u64 = 0x0102_1997;

#[cfg(test)]
mod tests;
