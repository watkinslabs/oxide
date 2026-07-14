// Module manifest: types owns endpoint state and queue; matching owns tuple
// admission; options owns ICMP/checksum policy; rx owns receive filtering;
// tx owns caller- and kernel-header send preparation.

mod matching;
mod options;
mod registry;
mod rx;
mod tx;
mod types;

pub use options::{Icmp6Filter, Raw6Checksum};
pub use rx::{Raw6RxDisposition, Raw6RxPacket};
pub use tx::{PreparedRaw6Send, Raw6SendMode};
pub use types::{Raw6Address, Raw6Datagram, Raw6Endpoint, Raw6RxMeta};
pub(crate) use registry::Raw6Table;

#[cfg(test)]
mod tests;
