//! Libc-owned thread factory; gate owns preparation/publication ordering,
//! platform owns NT ABI transitions, native owns the real attachment provider.
mod gate;
mod native;
mod platform;
pub use native::install_factory;
