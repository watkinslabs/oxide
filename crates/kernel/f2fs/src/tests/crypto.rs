//! File encryption, against known answers from independent implementations
//! of the specifications each step is defined by.
//!
//! A round trip proves almost nothing here: every wrong context byte, wrong
//! info string, wrong IV rule and wrong ciphertext-stealing convention
//! decrypts its own output perfectly. What separates them is agreement with
//! another implementation, so the derived keys and the ciphertexts below are
//! fixed values rather than "whatever we produce".
//!
//! Module manifest:
//! - `fixture`:  the one master key, nonce and volume every vector uses.
//! - `context`:  the stored context, parsed, refused and round-tripped.
//! - `support`:  which policies may be used, and why each refusal exists.
//! - `derive`:   every subkey the master key produces.
//! - `contents`: file bytes under each mode, and the four IV rules.
//! - `modes`:    the four modes beyond the AES pairings, against the
//!               primitives driven directly.
//! - `names`:    padding, name ciphertext, and the keyed directory hash.
//! - `nokey`:    the name a locked directory shows, and finding it again.
//! - `tree`:     inheritance, the same-policy rule, and symbolic links.
//! - `inline`:   handing contents encryption to the block layer, and the
//!               agreement between the two implementations that makes it safe.

#[path = "crypto/fixture.rs"] mod fixture;
#[path = "crypto/context.rs"] mod context;
#[path = "crypto/support.rs"] mod support;
#[path = "crypto/derive.rs"] mod derive;
#[path = "crypto/contents.rs"] mod contents;
#[path = "crypto/modes.rs"] mod modes;
#[path = "crypto/names.rs"] mod names;
#[path = "crypto/nokey.rs"] mod nokey;
#[path = "crypto/tree.rs"] mod tree;
#[path = "crypto/inline.rs"] mod inline;
