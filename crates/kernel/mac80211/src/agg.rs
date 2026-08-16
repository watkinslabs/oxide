// Block-ack aggregation.
//
// Module manifest:
// - `window`: sequence-number arithmetic and the window placement decision.
// - `tid_rx`: the reorder buffer and the receiving half of a session.
// - `tid_tx`: the negotiation and the originating half of a session.
// - `action`: the three action frames that set a session up and take it down.

#[path = "agg/window.rs"] pub mod window;
#[path = "agg/tid_rx.rs"] pub mod tid_rx;
#[path = "agg/tid_tx.rs"] pub mod tid_tx;
#[path = "agg/action.rs"] pub mod action;

pub use tid_rx::{ReorderBuf, RxAgg};
pub use tid_tx::{TidTx, TxAggState};
pub use window::{Placement, TxWindow, Window};
