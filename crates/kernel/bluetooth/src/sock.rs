//! The `AF_BLUETOOTH` socket family.
//!
//! The family registers through the socket layer's existing family owner; it
//! keeps no registry of its own, because a second one would let the two
//! disagree about which protocols exist.
//!
//! Module manifest:
//! - `create`: the two-screen admission a creation request passes.
//! - `addr`: the four address forms, one per protocol.
//! - `hci_sock`: the raw controller socket, its channels and its screens.
//! - `inode`: the file description a Bluetooth socket hangs off.
//! - `fanout`: delivering a frame to every socket that should see it.

pub mod create;
pub mod addr;
pub mod hci_sock;
pub mod inode;
pub mod fanout;

pub use create::{plan_create, BtSocket};
pub use hci_sock::{plan_bind, HciSocket};
pub use inode::{make_hci_socket_inode, HciSocketFile};
