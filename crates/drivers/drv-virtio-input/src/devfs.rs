mod fileops;
mod ioctl;
mod registry;
mod shared;

pub(crate) use shared::current_endpoint;
pub(crate) use registry::model_device;
#[cfg(test)]
pub use fileops::make_evdev_inode;
pub use ioctl::handle_evdev_ioctl;
pub use registry::{init, register_node, unregister_node};

#[cfg(test)]
pub(crate) mod tests;
