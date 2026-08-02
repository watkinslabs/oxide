// IPv4 header option area, both directions. Manifest only.
//
// Module manifest:
// - `uapi`: the option area's ABI numbers.
// - `area`: the compile pass over a caller-supplied area, its inverse, and the
//   compiled representation (`Compiled`) every transmit path carries.
// - `compile`: the namespace-aware entry every caller-supplied area enters by.
// - `rx`: the receive-side pass a delivered header runs, and the reply area
//   a receiver echoes back.
// - `emit`: the post-route fill pass, the per-fragment copy rule, and the
//   variable-length header writer every IPv4 transmit path uses.
// - `tests`: byte-exact coverage for the emitted header and its fragments.
// - `tests_rx`: byte-exact coverage for the receive-side fill and the echo.
//
// No target gate: every decision here must run under hosted `cargo test`, and
// the option level that admits these areas (`sock_opts::sol_ip`) is gated.

pub mod uapi;
pub mod area;
pub mod compile;
pub mod emit;
pub mod rx;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_rx;

pub use area::{AddrClass, Compiled, NoUnicast, Origin, build, build_packet, build_with, undo};
pub use compile::{RemoteUnicast, build_control, build_in};
pub use rx::{echo, received};
pub use emit::{Header, fill, fill_slots, fragment, fragmented, header_len, is_strict_route, timestamp,
    wire_dst, write_header};
