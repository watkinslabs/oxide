// The transmit path.
//
// Module manifest:
// - `port`:    the controlled-port rule, as a pure decision.
// - `frag`:    fragmentation against the threshold.
// - `encrypt`: the encryption step and the integrity code.
// - `chain`:   the ordered chain and the entry points the rest of the layer
//              transmits through.

#[path = "tx/chain.rs"] pub mod chain;
#[path = "tx/encrypt.rs"] pub mod encrypt;
#[path = "tx/frag.rs"] pub mod frag;
#[path = "tx/port.rs"] pub mod port;

pub use chain::{tx_mgmt, tx_payload, xmit_eth};
pub use port::{allowed, crosses_unauthorized_port, verdict, PortVerdict};
