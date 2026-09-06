extern crate alloc;
extern crate self as sched;
extern crate self as uaccess;
#[path="../src/nt_window/paint_prepare.rs"]mod paint_prepare;
#[path="../src/nt_window/paint_prepare/owner_boundary.rs"]mod owner_boundary;
#[path="../src/nt_window/paint_prepare/hosted.rs"]mod nt_window;
pub use nt_window::{live,thread_group,copy_to_user};
mod nt_gdi{pub(crate) use crate::nt_window::gdi_adapter::*;}
mod nt_milestone{pub(crate) fn paint_begin(){crate::nt_window::milestone();}}
