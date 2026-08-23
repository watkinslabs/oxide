#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

// Module manifest:
// - `uapi`: status bits, ctinfo values, ctnetlink attrs, protocol numbers.
// - `limits`: table sizes, expectation budgets, NAT port windows.
// - `tuple`: the flow key, its inversion, and ICMP type mapping.
// - `hash`: table hash and the source-only hash NAT reuse depends on.
// - `proto`: per-protocol trackers (TCP state machine, UDP, ICMP, generic).
// - `entry`: one tracked connection and its lifecycle bits.
// - `table`: the two-tuple hash, confirmation, GC, and early drop.
// - `expect`: announced connections and their mask matching.
// - `helper`: helper registry and the attach decision.
// - `event`: coalesced change notifications for ctnetlink listeners.
// - `sysctl`: the tunable set and its proc names.
// - `core`: the per-packet entry point tying trackers to the table.
// - `procfs`: `/proc/net/nf_conntrack` rendering.
// - `ctnetlink`: the ctnetlink message and attribute encoding.

pub mod uapi;
pub mod limits;
pub mod tuple;
pub mod hash;
pub mod proto;
pub mod entry;
pub mod table;
pub mod expect;
pub mod helper;
pub mod event;
pub mod sysctl;
pub mod core;
pub mod procfs;
pub mod ctnetlink;

pub use core::{CtNet, HelperChangeError, L4, Packet, Track};
pub use entry::{Conn, NatBinding, ProtoState, TimeoutPolicy};
pub use expect::{ExpectError, Expectation, ExpectTable, TupleMask};
pub use helper::{Helper, HelperAssign, HelperRegistry};
pub use table::{CtTable, Found};
pub use tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
