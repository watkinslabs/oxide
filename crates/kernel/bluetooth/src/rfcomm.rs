//! RFCOMM: serial port emulation over a single reliable channel.
//!
//! Module manifest:
//! - `fcs`: the frame check sequence and the coverage each frame type demands.
//! - `frame`: frame encode and decode, including the widening length field.
//! - `mcc`: the multiplexer command set and its payload layouts.
//! - `credit`: credit-based flow control in both directions.
//! - `rpn`: port negotiation and the parameter-mask semantics.
//! - `dlc`: one data link connection and its per-channel state.
//! - `session`: the multiplexer session and the link-control state machine.
//! - `mux`: multiplexer command handling.
//! - `pump`: queueing and the credit-paced transmit pass.
//! - `sock`: the socket surface — bind, listen, connect, and the listener table.
//! - `sockopt`: the option surface at both levels.
//! - `tty`: the terminal binding, its device registry and its ioctls.
//! - `link`: the contract with the channel below and the layer above.

pub mod fcs;
pub mod frame;
pub mod mcc;
pub mod credit;
pub mod rpn;
pub mod dlc;
pub mod session;
pub mod mux;
pub mod pump;
pub mod sock;
pub mod sockopt;
pub mod tty;
pub mod link;

pub use credit::CreditFlow;
pub use dlc::Dlc;
pub use frame::{Frame, FrameError};
pub use link::{DlcEvent, FrameLog, L2capTx, SessionHost};
pub use session::Session;
pub use sock::{Listeners, RfcommSock};

#[cfg(test)]
#[path = "rfcomm/tests/mod.rs"]
mod tests;
