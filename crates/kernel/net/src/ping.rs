// ICMP datagram endpoints — the unprivileged echo-probe socket class.
//
// An endpoint of this class is admitted by group membership rather than by the
// raw-network capability, and unlike a raw endpoint it can originate only echo
// probes. The echo identifier is kernel-owned: it is allocated at bind or at
// first transmit, stamped over whatever the caller wrote, and used as the sole
// key that steers replies and quoted errors back to the originating endpoint.
//
// Module manifest:
// - group:    the group window, its parse/format contract, and admission.
// - ident:    identifier allocation, the reuse rule, and the match ladder.
// - validate: echo-only message screening and identifier stamping.
// - sock:     endpoint lifecycle — admission, bind, autobind, release.
// - tx:       probe preparation.
// - rx:       reply and quoted-error demultiplexing.

pub mod group;
pub mod ident;
pub mod validate;
pub mod sock;
mod tx;
mod rx;

pub use group::{CallerGroups, GroupRange};
pub use ident::{PingIdent, PingSock, PingTable, ReplyTuple, UNBOUND};
pub use rx::Reply6;
pub use sock::{
    admits, PingDiag, autobind_v4, autobind_v6, bind_v4, bind_v6, group_range_for, new_ident, release,
    set_group_range_for,
};
pub use tx::{prepare_v4, prepare_v6};
pub use validate::{is_reply, supported, PingFamily};

#[cfg(test)]
#[path = "ping/tests.rs"]
mod tests;
