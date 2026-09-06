//! Module manifest: service registers/completes callbacks; context copies and enters native text.
mod service;
mod context;
mod measure;
mod query;
mod nonclient;
pub(crate) use nonclient::{begin_nonclient, begin_system_metric};
pub(crate) use service::dispatch;
pub(crate) use context::begin;
pub(crate) use measure::begin_measure;
pub(crate) use query::begin_query;
