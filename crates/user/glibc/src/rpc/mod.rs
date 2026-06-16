//! Sun RPC (docs/59§6 §9.1). XDR serialization first; clnt/svc/auth/pmap follow.
//! glibc keeps the RPC symbols in libc.so.6 for ABI compat though the headers
//! moved to libtirpc.
#![allow(clippy::upper_case_acronyms)]
#[cfg(feature = "freestanding")]
pub mod xdr;
