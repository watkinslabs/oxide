//! Production preparation/callback ordering; simulated recipient execution only at Send.
extern crate alloc;
extern crate self as sched;
extern crate self as uaccess;
#[path="../src/nt_window/paint_prepare.rs"]
mod paint_prepare;
#[path="null_paint_callbacks/fixture.rs"]
mod nt_window;
pub use nt_window::{live,thread_group,copy_to_user};
mod nt_gdi{pub(crate) use crate::nt_window::gdi::*;}
mod nt_milestone{pub(crate) fn paint_begin(){crate::nt_window::milestone();}}
