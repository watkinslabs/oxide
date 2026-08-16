//! Command response payloads — what follows the opcode and status inside a
//! command complete.
//!
//! Module manifest:
//! - `info`: the controller descriptions and capability reads.
//! - `conn`: the per-peer answers and the small handle-or-instance replies.
//!
//! A response that echoes the address it was asked about is `AddrInfo::encode`;
//! there is no separate type for each of those.

pub mod info;
pub mod conn;
