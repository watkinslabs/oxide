//! Display and DPI ordinals: device and mode enumeration, monitor DPI, the
//! per-monitor point conversions, display configuration and process layout.

#[path = "display/raw.rs"]
mod raw;
pub(crate) use raw::*;

#[path = "display/devmode.rs"]
pub(crate) mod devmode;

#[cfg(target_os = "oxide-kernel")]
#[path = "display/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::route;
