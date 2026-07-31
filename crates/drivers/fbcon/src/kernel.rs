extern crate alloc;

mod query;
#[cfg(test)]
mod tests;
mod runtime;
mod shared;

pub use query::{
    console_dims, fg_app_cursor, fg_bracketed_paste, force_repaint, foreground, resize_vt,
    screen_dump, scrolldelta,
};
pub use shared::{FlushFn, ReplyFn};
pub use runtime::{
    drain_answerback, kernel_init, kernel_unregister, set_reply_sink, set_vt_graphics_mode,
    switch_vt, tick_drain, vt_console_sink, vt_write,
};
