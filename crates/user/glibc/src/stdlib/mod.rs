//! stdlib — glibc-ABI surface, one fn/file (docs/59§3). Implemented at G7 (docs/59§6).
//! exit family lands early (G2) for the process-entry path.
pub mod exit;
pub mod env;
pub mod strto;
pub mod strtod;
pub mod sort;
pub mod rand;
#[cfg(feature = "freestanding")]
pub mod stdbit;
#[cfg(feature = "freestanding")]
pub mod arith;
#[cfg(feature = "freestanding")]
pub mod realpath;
#[cfg(feature = "freestanding")]
pub mod mkstemp;
#[cfg(feature = "freestanding")]
pub mod mkdtemp;
#[cfg(feature = "freestanding")]
pub mod subopt;
#[cfg(feature = "freestanding")]
pub mod a64l;
#[cfg(feature = "freestanding")]
pub mod fmtmsg;
#[cfg(feature = "freestanding")]
pub mod rand48;
#[cfg(feature = "freestanding")]
pub mod fcvt;
