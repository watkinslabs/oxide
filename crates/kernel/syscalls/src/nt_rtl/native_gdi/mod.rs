//! Module manifest: service registers/completes callbacks; context copies and enters native text.
mod service;
mod context;
mod measure;
mod query;
mod nonclient;
mod menu_cells;
pub(crate) use nonclient::{begin_nonclient_at, begin_system_metric};
pub(crate) use service::{dispatch, has_font_backend};
pub(crate) use context::{begin, begin_kernel_text};
pub(crate) use measure::begin_measure;
pub(crate) use query::begin_query;
pub(crate) use menu_cells::{begin_menu_cells, note_asked};
