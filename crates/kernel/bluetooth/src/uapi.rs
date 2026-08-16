//! Wire and ABI constants, one module per protocol.
//!
//! Module manifest:
//! - `bt`: family-wide address, protocol selectors, shared option numbers.
//! - `hci`,`hci_cmd`,`hci_evt`: controller framing, opcodes, event codes.
//! - `hci_sock`,`hci_mon`: the raw HCI socket ABI and the monitor framing.
//! - `l2cap`,`smp`,`rfcomm`,`sco`,`mgmt`: per-protocol wire constants.

pub mod bt;
pub mod hci;
pub mod hci_cmd;
pub mod hci_evt;
pub mod hci_sock;
pub mod hci_mon;
pub mod l2cap;
pub mod smp;
pub mod rfcomm;
pub mod sco;
pub mod mgmt;
