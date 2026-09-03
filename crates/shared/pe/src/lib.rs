#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
extern crate alloc;
#[cfg(any(test, feature = "hosted"))] extern crate std;
mod parser;
pub use parser::*;
pub mod nt_stub;
pub mod catalog;
pub mod apiset;
pub mod loader_list;
#[cfg(test)] mod tests;
