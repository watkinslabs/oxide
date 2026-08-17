//! The built-in signature: the blob that gets signed, the policy that decides
//! what is acceptable, and a real signed file read end to end.
//!
//! Module manifest:
//! - `fixtures`: certificates and signatures from an outside toolchain.
//! - `policy`:   what is accepted and refused, and with which answer.
//! - `sealed`:   sealing a file under a signature and reading it back.

#[path = "veritysig/fixtures.rs"] mod fixtures;
#[path = "veritysig/policy.rs"] mod policy;
#[path = "veritysig/sealed.rs"] mod sealed;
