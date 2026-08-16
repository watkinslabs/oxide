// 802.3ad link aggregation.
//
// Module manifest:
//   pdu — LACPDU wire layout: encode, length-validated decode, TLV constants.
//   sm  — receive / periodic / mux / transmit machine states and transitions.
//   agg — aggregator comparison and the ad_select selection policies.

pub mod pdu;
pub mod sm;
pub mod agg;

pub use pdu::{Lacpdu, PortInfo, LACP_SUBTYPE, LACP_VERSION};
pub use sm::{ChurnState, MuxState, PeriodicState, RxState, TxState};
pub use agg::{Aggregator, agg_selection_test, select_aggregator};
