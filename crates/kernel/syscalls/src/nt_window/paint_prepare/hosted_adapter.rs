pub(crate) use crate::paint_prepare::{Prepared,Owner,finish,whole_window_covered};
#[path="live.rs"]mod live;
#[path="factory.rs"]mod factory;
pub(crate) use live::{begin_for_current,finish_for_current,discard_for_current};
pub(crate) use factory::prepare_for_current;
