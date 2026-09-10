//! Compile the three production notification-owner modules together.
#[path = "../../families/hook_api.rs"]
pub mod hook_api;
#[path = "../../families/hook_event.rs"]
mod hook_event;
#[path = "../../families/hook_state.rs"]
mod hook_state;
