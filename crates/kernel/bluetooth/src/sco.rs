//! SCO and eSCO: synchronous voice links.
//!
//! Module manifest:
//! - `param`: the parameter tables, the fallback walk and the capability screen.
//! - `cmd`: the setup and accept command parameter encodings.
//! - `conn`: one link, its attempts and what a completion event means.
//! - `sock`: the socket surface and every option's state window.
//! - `data`: the voice data path and the reception-status ancillary.
//! - `link`: the contract with the controller.

pub mod param;
pub mod cmd;
pub mod conn;
pub mod sock;
pub mod data;
pub mod link;

pub use cmd::{AcceptSyncConn, SetupSyncConn};
pub use conn::{Outcome, SyncLink};
pub use link::{CmdLog, ScoTx};
pub use param::{LinkCaps, ParamError, ScoParam};
pub use sock::ScoSock;

#[cfg(test)]
#[path = "sco/tests/mod.rs"]
mod tests;
