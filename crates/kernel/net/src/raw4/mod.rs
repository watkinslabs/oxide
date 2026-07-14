// Raw IPv4 module manifest.
// - types: endpoint-owned lifecycle and receive queue.
// - registry: canonical per-network-namespace protocol table.
// - error: quoted-packet matching and pending error publication.
// - reassembly: first-header-preserving fragment assembly.
// - rx: exact-protocol receive fanout and socket filtering.
// - tx: arbitrary-protocol header construction and transmission.

mod types;
mod registry;
mod error;
mod reassembly;
mod rx;
mod tx;

pub use types::{Raw4Datagram, Raw4Endpoint, Raw4StateSnapshot, Raw4TxOptions};
pub(crate) use registry::Raw4Table;

#[cfg(test)]
mod tests;
