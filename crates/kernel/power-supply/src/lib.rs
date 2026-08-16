// Linux power-supply class. Owns the registered supplies, the property
// contract with its units, the per-supply attribute visibility rule, and the
// change path a power daemon watches. Contains no filesystem code: `sysfs`
// projects this registry, and provider crates register into it.
//
// Module manifest:
// - `values`: enumerated property values and their exact sysfs text.
// - `uapi`: the property enumeration and its attribute/kind table.
// - `supply`: one registered supply, its declaration and get/set ladder.
// - `format`: value rendering, space escaping, and store-side parsing.
// - `attrs`: attribute visibility, show/store, and the uevent environment.
// - `registry`: the class supply list, registration, and the change path.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod attrs;
pub mod format;
pub mod registry;
pub mod supply;
pub mod uapi;
pub mod values;

pub use registry::{by_name, changed, count, register, set_change_hook, supplies, unregister};
pub use supply::{PowerSupply, PropVal, SupplyDesc, SupplyOps};
pub use uapi::{Kind, Property, PROPERTY_COUNT};
pub use values::{CapacityLevel, ChargeType, Health, PsyType, Scope, Status, Technology, UsbType,
                 CLASS_NAME};
