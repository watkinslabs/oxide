//! The control framework: what a device's knobs are, what values they admit,
//! and how an application discovers and moves them.
//!
//! Module manifest:
//! - `range`: range coherence and the snap-to-step rule.
//! - `desc`: control descriptions, live values, clusters, the handler.
//! - `query`: `QUERYCTRL`, `QUERY_EXT_CTRL`, the walk, `QUERYMENU`.
//! - `access`: `G_CTRL`/`S_CTRL` and the extended batch forms.
//! - `standard`: the control descriptions a camera is expected to have.

pub mod range;
pub mod desc;
pub mod query;
pub mod access;
pub mod standard;

pub use desc::{ControlDesc, Handler};
pub use access::{ExtEntry, Written};
pub use query::MenuEntry;
