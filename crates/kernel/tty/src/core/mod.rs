// Module manifest:
// - `api`: public tty-core enums and the driver trait surface.
// - `tty`: `TtyStruct` state, blocking I/O, and lifecycle operations.

mod api;
mod tty;

pub use api::{ReadOutcome, TtyDriver, TtyFlow, TtyFlush};
pub use tty::TtyStruct;

#[cfg(test)]
mod tests;
