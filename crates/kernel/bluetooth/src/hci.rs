//! HCI core: the controller abstraction every protocol above sits on.
//!
//! Module manifest:
//! - `packet`: H:4 framing, header parsing, the streaming decoder.
//! - `cmd`: command queue, credit accounting, the two deadlines.
//! - `conn`: baseband connection tracking, keyed by handle and by peer.
//! - `event`: event dispatch and the state each event changes.
//! - `init`: the setup sequence a controller runs before it is usable.
//! - `dev`: controller registry, the `hci` index, per-controller state.
//! - `transport`: the contract a transport driver implements.
//! - `filter`: the raw-socket packet and event filter.
//! - `mon`: monitor framing, the record `btmon` reads.

pub mod packet;
pub mod cmd;
pub mod conn;
pub mod event;
pub mod init;
pub mod dev;
pub mod transport;
pub mod filter;
pub mod mon;

pub use conn::{Conn, ConnList, PeerId};
pub use packet::{Frame, H4Decoder};
pub use transport::HciTransport;
