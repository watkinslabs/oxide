// Module manifest:
// - `api`: public tty-core enums and the driver trait surface.
// - `lifecycle`: open/close/exclusive/hangup lifecycle helpers.
// - `tty`: `TtyStruct` state, blocking I/O, and lifecycle operations.
// - `flip`: Linux `tty_buffer.c`'s flip ring — the staging area that keeps the
//   line discipline out of the device interrupt handler.

mod api;
pub mod flip;
mod lifecycle;
mod tty;

pub use api::{ReadOutcome, TtyDriver, TtyFlow, TtyFlush};
pub use flip::{FlipRing, FLIP_CAPACITY, FLUSH_CHUNK};
pub use tty::TtyStruct;

#[cfg(test)]
mod tests;
