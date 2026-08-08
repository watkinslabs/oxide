// Socket work-layer manifest.
// - `error`: typed work errors and backend translations.
// - `message`: kernel-owned send inputs and outcomes.
// - `target`: retained open-file classification.
// - `send`: family routing, retry, and SIGPIPE completion.
// - `address`: kernel-snapshot socket-address decoding and UNIX lookup.
// - `cmsg_walk`: the one send-side ancillary cursor every rule iterates.
// - `control`: the SCM rule (AF_UNIX descriptors and credentials, NETLINK).
// - `control_raw`: the IP-level rule and its transmit overrides.
// - `control_family`: WHICH of the rules a socket's family speaks.
// - `sockcm`: the generic SOL_SOCKET rule every non-SCM family runs.
// - `vsock_addr`: AF_VSOCK send-destination admission.
// - `oob`: AF_UNIX out-of-band send division.
// - `packet`: AF_PACKET message transmission.
// - `batch`: lazy sendmmsg import/publication policy.
// - `receive`: SCM_RIGHTS receive descriptor publication.
// - `security`: the one send-side security hook call site.
// - `filter`: common socket-filter target and mutation work.
// - `test_support`: hosted-suite ownership of the process-global policy and
//   AF_UNIX rights state, checked at the choke points that reach them.

#![no_std]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;
#[cfg(test)]
extern crate std;

mod address;
mod batch;
mod cmsg_walk;
mod control;
mod control_family;
mod control_raw;
mod error;
mod filter;
mod ids;
mod message;
mod oob;
mod packet;
mod receive;
mod security;
mod send;
mod sockcm;
mod target;
mod vsock_addr;

pub use batch::{BatchIo, BatchSpec, UIO_MAXIOV, send_batch};
pub use error::{Error, KResult};
pub use filter::{FilterError, FilterFile};
pub use message::{Message, SendOutcome};
pub use oob::{unix_oob_plan, UnixOobPlan};
pub use receive::{ReceiveFdResult, install_received_fds};
pub use send::{ImportMode, MessageIo, SendContext, send, send_io, write, writev};
pub use target::{SendFile, SendKind};

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod packet_tests;
#[cfg(test)]
mod control_raw_tests;
#[cfg(test)]
mod receive_tests;
#[cfg(test)]
mod filter_tests;
#[cfg(test)]
#[path = "tests/netlink_preflight.rs"]
mod netlink_preflight_tests;
#[cfg(test)]
#[path = "tests/security_hooks.rs"]
mod security_hooks_tests;
