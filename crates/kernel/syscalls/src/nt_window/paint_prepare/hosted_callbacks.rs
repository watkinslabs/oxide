#[path="../paint_callbacks/work.rs"]mod work;
pub(crate) use work::*;
#[path="../paint_callbacks/live.rs"]mod live;
pub(crate) use live::{for_current,cancel_current_thread,cancel_window_current,reap_retired_current};
