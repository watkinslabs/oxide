// `TCP_ZEROCOPY_RECEIVE` — the receive window a TCP socket's `mmap(2)`
// establishes, and the option's byte-moving half.
//
// Module manifest:
// - `window`: the mapped window object, its refcounted page store, and the
//   `mmap(2)` admission for a socket fd.
// - `receive`: the option's copy-in / plan / remap / copy-out shim.
//
// The decisions — operand layout, optlen versioning, errno ordering, and every
// output-field rule — live in `net::sock_opts::sol_tcp::zerocopy` (`docs/53§4`).

pub mod window;
#[cfg(target_os = "oxide-kernel")]
pub mod receive;

pub use window::{TcpZcWindow, mmap_backing};
