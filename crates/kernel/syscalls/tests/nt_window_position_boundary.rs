//! Production position callbacks and canonical IPC owner; hosted scheduler, copy and publication boundaries.
#![allow(dead_code,unused_imports)]
extern crate alloc;
extern crate self as sched;
extern crate self as uaccess;
#[path="../src/nt_window/tests/position_hosted.rs"] mod nt_window;
#[path="../src/nt_window/tests/position_boundary/environment.rs"] mod environment;
pub use environment::{live,thread_group,nt_callback,copy_from_user};
use environment::{nt_rtl,nt_gdi};
#[path="../src/nt_window/tests/position_boundary/wine.rs"] mod position_adapter;
mod nt_wine_window {pub(crate) use crate::position_adapter as position;}
