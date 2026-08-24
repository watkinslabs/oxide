#![no_std]
// Link aggregation master per `25`.
//
// Module manifest:
//   uapi    — mode ids, hash-policy ids, IFLA_BOND_* numbers, enumerated value tables.
//   flags   — LACP state bits, port flags, option dependency flags.
//   limits  — table sizes, value bounds, timer periods, wire lengths.
//   slave   — per-port state the decision modules read.
//   hash    — flow dissection and the six transmit-hash policies.
//   mode    — per-mode transmit slave selection.
//   link    — MII monitor phase machine and ARP monitor validation.
//   select  — active-slave choice, reselection policies, peer-notification gate.
//   options — the option table and its dependency check.
//   lacp    — 802.3ad: wire format, port machines, aggregator selection.
//   tlb     — transmit load balancing table.
//   alb     — receive load balancing client table.
//   master  — the bond master device and enslave/release.
//   netlink — IFLA_BOND_* blob to checked option writes.

extern crate alloc;

pub mod uapi;
pub mod flags;
pub mod limits;
pub mod slave;
pub mod hash;
pub mod mode;
pub mod link;
pub mod select;
pub mod options;
pub mod lacp;
pub mod tlb;
pub mod alb;
pub mod master;
pub mod netlink;
pub mod link_kind;
pub mod view;

pub use master::{BondMaster, BondParams, BondSlave};
pub use slave::{LinkState, SlaveRole, SlaveState};
pub use hash::{bond_xmit_hash, dissect, FlowKeys};
pub use mode::{select_tx, TxContext, TxTarget};
pub use view::{BondView, BondSlaveView};

#[cfg(test)] #[path = "tests/hash.rs"] mod tests_hash;
#[cfg(test)] #[path = "tests/mode.rs"] mod tests_mode;
#[cfg(test)] #[path = "tests/link.rs"] mod tests_link;
#[cfg(test)] #[path = "tests/select.rs"] mod tests_select;
#[cfg(test)] #[path = "tests/options.rs"] mod tests_options;
#[cfg(test)] #[path = "tests/lacp_pdu.rs"] mod tests_lacp_pdu;
#[cfg(test)] #[path = "tests/lacp_agg.rs"] mod tests_lacp_agg;
#[cfg(test)] #[path = "tests/lacp_sm.rs"] mod tests_lacp_sm;
#[cfg(test)] #[path = "tests/balance.rs"] mod tests_balance;
#[cfg(test)] #[path = "tests/netlink.rs"] mod tests_netlink;
#[cfg(test)] #[path = "tests/link_kind.rs"] mod tests_link_kind;
