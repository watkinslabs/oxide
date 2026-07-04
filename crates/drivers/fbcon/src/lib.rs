#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod console;
mod parser;

pub use console::{xterm_256, Console, VGA_PALETTE};
pub use parser::{step, Action, CsiState, ParserState};

pub mod font;
pub mod vcrender;

#[cfg(test)]
mod tests;

pub mod answerback;
pub mod kernel;
