//! Security Manager Protocol: pairing, key derivation, key storage and
//! security-level sufficiency.
//!
//! Module manifest:
//! - `crypto`: the specification's crypto functions and the byte-order
//!   reversal every one of them performs.
//! - `pdu`: the wire codec and its length validation.
//! - `method`: the pairing-method tables and the overrides on top of them.
//! - `level`: what a requirement asks for, what a key provides, whether a link
//!   already satisfies a request, and the key-size bounds.
//! - `keys`: distributed key records, the store, and address resolution.
//! - `session`: per-link state, configuration and the event list a step emits.
//! - `legacy`: temporary key selection, the confirm exchange, the short-term key.
//! - `sc`: public key exchange, shared secret, confirm and check values.
//! - `dist`: the key distribution phase.
//! - `xtransport`: deriving one transport's key from the other's.
//! - `chan`: frame dispatch, the two ways a pairing starts, user answers.

pub mod crypto;
pub mod pdu;
pub mod method;
pub mod level;
pub mod keys;
pub mod session;
pub mod legacy;
pub mod sc;
pub mod dist;
pub mod xtransport;
pub mod chan;

pub use keys::{Csrk, Irk, KeyStore, LinkKey, Ltk};
pub use level::{KeyPref, authreq_to_seclevel, check_enc_key_size, seclevel_to_authreq,
                sufficient_security};
pub use pdu::{PairingCmd, Pdu, decode};
pub use session::{Entropy, LinkAddrs, Smp, SmpConfig, SmpEvent};

#[cfg(test)]
#[path = "smp/tests/mod.rs"]
mod tests;
