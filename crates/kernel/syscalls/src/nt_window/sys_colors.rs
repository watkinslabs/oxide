//! `NtUserSetSysColors`: replace named system colours, then tell every window.

#[path = "sys_colors/raw.rs"]
mod raw;
pub(crate) use raw::ORDINAL;

#[cfg(target_os = "oxide-kernel")]
#[path = "sys_colors/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::route;
