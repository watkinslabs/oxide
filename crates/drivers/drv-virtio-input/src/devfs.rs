mod fileops;
mod ioctl;
mod registry;
mod shared;

pub use fileops::{make_evdev_inode, notify_evdev_subs};
pub use ioctl::handle_evdev_ioctl;
pub use registry::{init, register_node, unregister_node};

#[cfg(test)]
mod tests;
