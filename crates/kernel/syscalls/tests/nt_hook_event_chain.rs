//! Actual hook registry adapter, client record and callback completion router.
#![allow(dead_code)] // Neighbor hook APIs and unrelated completion arms are outside this fixture.
extern crate alloc;
#[path = "../src/nt_window/tests/hook_chain/environment.rs"]
mod environment;
use environment::{sched, timekeeper, Spinlock, GuiLockClass, STATUS_PENDING};
#[path = "../src/nt_window/tests/hook_chain/families.rs"]
mod families;
use families::hook_api::{CALLBACK_WIN_EVENT, hook_complete_event};
#[path = "../src/nt_window/callbacks.rs"]
mod callbacks;
#[path = "../src/nt_window/tests/hook_chain/cases.rs"]
mod cases;
mod nt_window { pub use crate::environment::send; }
use environment::{create, position, send, scroll, CALLBACK_INIT_BUILTIN_CLASSES};
mod nt_user_callback { pub enum Input<'a> { Record(&'a [u8]) } }
mod nt_rtl {
    pub use crate::environment::begin_user_callback;
    pub fn begin_hook_callback(_: u64, _: u64, _: u64, _: u64) -> u64 { panic!("window hooks belong to their own fixture") }
}
