//! Which loop devices exist, and their published block-layer identity.
//!
//! `control` decides what an index request means; this module is what holds
//! the index and performs the decision. The split is deliberate — the rules
//! are tested against a plain list of entries, and this owns the one place a
//! device is published to or withdrawn from the block registry.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::registry::{BlockDriver, MajorRequest};
use syscall::errno::Errno;
use sync::{Spinlock, TaskList as LoopLockClass};

use crate::control::{self, Action, Entry, State};
use crate::device::LoopDevice;
use crate::uapi::LOOP_MAJOR;

/// The block driver every `/dev/loopN` publishes under. The major is the one
/// the reference assigns, not a dynamic one: `losetup` and every udev rule
/// address these devices by name, and tools that parse `/proc/devices` expect
/// the fixed number.
pub const LOOP_DRIVER: BlockDriver = BlockDriver { name: "loop", major: MajorRequest::Fixed(LOOP_MAJOR) };

/// Devices created before anything asks for one.
///
/// The reference creates a fixed minimum at initialisation and lets the
/// control node create more on demand. Zero would work — `GET_FREE` creates
/// one — but a distribution's early boot opens `/dev/loop0` directly, before
/// anything has spoken to the control node.
pub const MIN_COUNT: u32 = 8;

struct Registered { number: u32, dev: Arc<LoopDevice> }

static DEVICES: Spinlock<Vec<Registered>, LoopLockClass> = Spinlock::new(Vec::new());

/// `/dev/loopN` for `number`. # C: O(1)
pub fn device_name(number: u32) -> String { format!("loop{number}") }

/// Every device this driver has published, as the index the control decisions
/// act on. The opener count comes from the block registry, which is the one
/// owner of that fact — a second count here could disagree with the one that
/// actually gates removal. # C: O(N)
pub fn index() -> Vec<Entry> {
    let devices = DEVICES.lock();
    devices.iter().map(|r| Entry {
        number: r.number,
        state: if r.dev.is_bound() { State::Bound } else { State::Unbound },
        openers: block::registry::opener_count(&device_name(r.number)).unwrap_or(0),
    }).collect()
}

/// The device behind `number`, or `None` when no such device exists.
/// # C: O(N)
pub fn device(number: u32) -> Option<Arc<LoopDevice>> {
    DEVICES.lock().iter().find(|r| r.number == number).map(|r| Arc::clone(&r.dev))
}

/// Create and publish one device. Idempotence is the caller's business:
/// `control::add` has already refused a duplicate. # C: O(N)
fn publish(number: u32) -> Result<u32, Errno> {
    let dev = Arc::new(LoopDevice::new(number));
    let name = device_name(number);
    let index = block::registry::register_with_driver(LOOP_DRIVER, &name, None, Arc::clone(&dev) as Arc<dyn block::BlockDevice>);
    if index == u32::MAX { return Err(Errno::Enomem); }
    DEVICES.lock().push(Registered { number, dev });
    Ok(number)
}

/// Withdraw one device. # C: O(N)
fn withdraw(number: u32) -> Result<(), Errno> {
    let mut devices = DEVICES.lock();
    let at = devices.iter().position(|r| r.number == number).ok_or(Errno::Enodev)?;
    devices.remove(at);
    drop(devices);
    block::registry::unregister(&device_name(number));
    Ok(())
}

/// `LOOP_CTL_ADD`. # C: O(N)
pub fn add(requested: i64) -> Result<u32, Errno> {
    match control::add(&index(), requested)? {
        Action::Add(number) => publish(number),
        _ => Err(Errno::Einval),
    }
}

/// `LOOP_CTL_REMOVE`. # C: O(N)
pub fn remove(requested: i64) -> Result<u32, Errno> {
    match control::remove(&index(), requested)? {
        Action::Remove(number) => { withdraw(number)?; Ok(number) }
        _ => Err(Errno::Einval),
    }
}

/// `LOOP_CTL_GET_FREE`. Reports a free device, creating one only when every
/// existing device is in use. # C: O(N)
pub fn get_free() -> Result<u32, Errno> {
    match control::get_free(&index())? {
        Action::Report(number) => Ok(number),
        Action::Add(number) => publish(number),
        Action::Remove(_) => Err(Errno::Einval),
    }
}

/// Publish the initial devices. Boot path, once. # C: O(MIN_COUNT)
pub fn init() {
    for number in 0..MIN_COUNT {
        if publish(number).is_err() { break; }
    }
}

/// Hosted-test-only reset — production never withdraws the whole index.
/// # C: O(N)
#[cfg(any(test, feature = "hosted"))]
pub fn _test_reset() {
    let numbers: Vec<u32> = DEVICES.lock().iter().map(|r| r.number).collect();
    for number in numbers { let _ = withdraw(number); }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published name is what `losetup` and every udev rule address.
    #[test]
    fn devices_are_named_as_the_reference_names_them() {
        assert_eq!(device_name(0), "loop0");
        assert_eq!(device_name(11), "loop11");
    }

    /// The major is the reference's fixed one, not a dynamically allocated
    /// number: tools read it out of `/proc/devices` and out of `mknod` calls
    /// that predate the running kernel.
    #[test]
    fn the_driver_owns_the_reference_major() {
        assert_eq!(LOOP_DRIVER.major, MajorRequest::Fixed(7));
        assert_eq!(LOOP_DRIVER.name, "loop");
    }

    /// A distribution opens `/dev/loop0` before it ever speaks to the control
    /// node, so some devices exist before anything asks.
    #[test]
    fn some_devices_exist_before_anything_asks() {
        assert!(MIN_COUNT > 0);
    }
}
