//! Test manifest.
//!
//! These pin the SHAPE of each mode — the stealing rule, the swap, the tweak
//! sequence — over a toy permutation, because shape is what a mode owns. The
//! published known-answer vectors live with the ciphers, in `aes` and `sm4`:
//! a mode's numbers are only meaningful against a real block transform.

#[path = "toy.rs"] mod toy;
#[path = "cbc.rs"] mod cbc;
#[path = "xts.rs"] mod xts;
