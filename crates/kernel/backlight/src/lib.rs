// Linux backlight class. Owns the registered backlight devices, the
// brightness/power rules the class applies before a driver is ever called,
// and the `/sys/class/backlight/<name>/` attribute contract. Contains no
// filesystem code: `sysfs` projects this registry, and provider crates
// register into it.
//
// Module manifest:
// - `uapi`: class ABI enums, power states, `state` bits, event sources.
// - `device`: per-device properties, driver vtable, blank/brightness rules.
// - `registry`: the class device list, registration, lookup, notification.
// - `attrs`: the sysfs attribute table and its show/store decisions.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod attrs;
pub mod device;
pub mod registry;
pub mod uapi;

pub use device::{BacklightDevice, BacklightOps, Properties};
pub use registry::{by_name, by_type, changed, count, devices, force_update, register,
                   set_change_hook, unregister};
pub use uapi::{BacklightScale, BacklightType, UpdateReason, BACKLIGHT_POWER_OFF,
               BACKLIGHT_POWER_ON, BL_CORE_FBBLANK, BL_CORE_SUSPENDED, CLASS_NAME};
