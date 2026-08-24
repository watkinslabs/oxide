// Thermal zone and cooling-device class. Owns the trip ladder with its
// hysteresis, the governors, the binding between a zone and the devices that
// can cool it, the polling cadence, and the terminal action a machine takes
// when it reaches the temperature past which its hardware is damaged.
//
// Contains no filesystem code and no firmware code: `sysfs` projects this
// registry, and provider crates register into it.
//
// Module manifest:
// - `uapi`: trip categories, mode text, sentinels, class device names.
// - `limits`: name bounds, poll cadences, the sensor-failure backoff.
// - `trip`: one trip point and where the temperature sits relative to it.
// - `update`: crossing detection, the hysteresis rule, the interrupt window.
// - `monitor`: which cadence a zone is read at, and what a failed read costs.
// - `cdev`: a cooling device, its range and its transition statistics.
// - `governor`: the policies, each a pure function over a zone snapshot.
// - `zone`: the zone object, its update pass, and cooling-device binding.
// - `registry`: the class lists, registration, aggregation, and the tick.
// - `attrs`: the `/sys/class/thermal` attribute contract.
// - `poll`: the kernel-side worker that drives the tick (kernel builds only).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod attrs;
pub mod cdev;
pub mod governor;
pub mod limits;
pub mod monitor;
pub mod registry;
pub mod trip;
pub mod uapi;
pub mod update;
pub mod zone;

#[cfg(target_os = "oxide-kernel")]
pub mod poll;

pub use cdev::{CoolingDevice, CoolingOps};
pub use governor::{available_names, by_name, Governor};
pub use monitor::Cadence;
pub use registry::{apply_cdev, cdev_by_name, cooling_devices, device_names, next_deadline_ns,
                   rebind_zone, reconfigure_zone, register_cdev, register_cdev_for_path, register_zone,
                   set_change_hook, set_critical_hook, unregister_zone,
                   set_crossing_hook, tick, unregister_cdev, update_all, update_zone,
                   zone_by_name, zones};
#[cfg(test)]
pub use registry::clear_for_tests;
pub use trip::{Bucket, Trip, TripDesc};
pub use uapi::{Direction, Mode, Trend, TripType, CLASS_NAME, NO_LIMIT, NO_TARGET, TEMP_INVALID};
pub use zone::{BindSpec, ThermalZone, ZoneDesc, ZoneOps};
