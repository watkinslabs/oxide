// `/sys/class/input` plus physical/virtual Linux inputN/eventN topology.
//
// Module manifest:
// - `model`: joins the canonical input record to its live driver-model node.
// - `device`: inputN/eventN directories and their uevent files.
// - `attrs`: inputN identity and capability attributes.
// - `inhibited`: writable inputN delivery state.
// - `class`: `/sys/class/input` projection and subsystem initialization.
// - `topology`: physical transport and parentless virtual containers.
// - `projection`: uevents and reverse-index paths consumed by the bus layer.

mod attrs;
mod class;
mod device;
mod inhibited;
mod model;
mod projection;
mod topology;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod vfs_tests;
#[cfg(test)]
pub(crate) use tests::INPUT_TEST_MUTEX;

pub use class::init;
pub(crate) use projection::{
    dev_devpath, dev_index_target, emit_device_add, emit_device_remove, related_paths,
};
pub(crate) use topology::{has_parented_inputs, make_transport_input_dir};
