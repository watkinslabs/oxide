pub(crate) use super::contract::ErasePrepared;
#[path="../redraw/erase_live.rs"]mod live;
pub(crate) use live::{begin_for_current,finish_for_current,discard_for_current};
