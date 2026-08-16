//! L2CAP: channels multiplexed over one baseband link, the signalling that
//! opens and configures them, and the two flow-control disciplines they run.
//!
//! Module manifest:
//! - `codec`: little-endian primitives, the basic header, the command header.
//! - `sig_bredr`: connect, disconnect, echo, information, command reject.
//! - `sig_conf`: configuration framing and the option list.
//! - `sig_le`: parameter update, credit-based connect, credits, the enhanced
//!   credit-based variants.
//! - `chan`: channel identity, state, progress bits and flags.
//! - `config`: what to propose, how to answer, how to fold an answer back.
//! - `ctrl`: the control field in both widths, and sequence arithmetic.
//! - `sar`: segmentation and reassembly for both disciplines.
//! - `ertm_tx`: send window, acknowledgement, retransmission, transmitter
//!   machine.
//! - `ertm_rx`: sequence classification and the receiver machine.
//! - `credit`: credit accounting, the ceiling, credit-mode receive.
//! - `security`: whether a link provides what a channel requires.
//! - `sock`: the address, the multiplexer screen, the option decisions.

pub mod codec;
pub mod sig_bredr;
pub mod sig_conf;
pub mod sig_le;
pub mod chan;
pub mod config;
pub mod ctrl;
pub mod sar;
pub mod ertm_tx;
pub mod ertm_rx;
pub mod credit;
pub mod security;
pub mod sock;

pub use chan::Channel;
pub use codec::{CmdHdr, Hdr};
pub use ctrl::Ctrl;
pub use security::{admissible, LinkSecurity, Verdict};
pub use sock::SockAddrL2;
