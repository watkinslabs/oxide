// IPv4 header option area on transmit. Manifest only.
//
// Module manifest:
// - `uapi`: the option area's ABI numbers.
// - `area`: the compile pass over a caller-supplied area, its inverse, and the
//   compiled representation (`Compiled`) every transmit path carries.
// - `compile`: the namespace-aware entry every caller-supplied area enters by.
// - `emit`: the post-route fill pass, the per-fragment copy rule, and the
//   variable-length header writer every IPv4 transmit path uses.
// - `tests`: byte-exact coverage for the emitted header and its fragments.
//
// No target gate: every decision here must run under hosted `cargo test`, and
// the option level that admits these areas (`sock_opts::sol_ip`) is gated.

pub mod uapi;
pub mod area;
pub mod compile;
pub mod emit;
#[cfg(test)]
mod tests;

pub use area::{AddrClass, Compiled, NoUnicast, build, build_with, undo};
pub use compile::{RemoteUnicast, build_control, build_in};
pub use emit::{Header, fill, fragment, fragmented, header_len, is_strict_route, timestamp,
    wire_dst, write_header};
