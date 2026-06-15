//! stdlib — glibc-ABI surface, one fn/file (docs/59§3). Implemented at G7 (docs/59§6).
//! exit family lands early (G2) for the process-entry path.
pub mod exit;
pub mod strto;
pub mod sort;
#[cfg(feature = "freestanding")]
pub mod arith;
