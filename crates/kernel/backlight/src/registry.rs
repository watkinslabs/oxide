// The backlight class itself: the registered device list, registration and
// unregistration, lookup, and the change-notification hook the sysfs layer
// installs to turn a class-level change into a uevent.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use crate::device::{BacklightDevice, BacklightOps, Properties};
use crate::uapi::{BacklightType, UpdateReason};

/// Change-notification callback: device name plus the `SOURCE=` value of the
/// event to generate.
pub type ChangeHook = fn(&str, &str);

static DEVICES: Spinlock<Vec<Arc<BacklightDevice>>, Devices> = Spinlock::new(Vec::new());
static CHANGE_HOOK: Spinlock<Option<ChangeHook>, Devices> = Spinlock::new(None);

/// Install the class change-notification callback. # C: O(1)
pub fn set_change_hook(hook: ChangeHook) { *CHANGE_HOOK.lock() = Some(hook); }

/// Register a backlight device. A duplicate name is refused with `EEXIST`:
/// the class directory is a namespace, and two devices answering to one name
/// would hand userspace a slider that controls whichever one it happened to
/// resolve. # C: O(N_devices)
pub fn register(
    name: &str,
    props: Properties,
    ops: Arc<dyn BacklightOps>,
) -> KResult<Arc<BacklightDevice>> {
    let mut devices = DEVICES.lock();
    if devices.iter().any(|dev| dev.name() == name) { return Err(VfsError::Eexist); }
    let dev = Arc::new(BacklightDevice::new(String::from(name), props, ops));
    devices.push(Arc::clone(&dev));
    drop(devices);
    changed(&dev, UpdateReason::Sysfs);
    Ok(dev)
}

/// Unregister a device. The driver vtable is dropped first so a store racing
/// the removal reports `ENXIO` rather than reaching a departing driver.
/// # C: O(N_devices)
pub fn unregister(dev: &Arc<BacklightDevice>) -> bool {
    dev.detach();
    let mut devices = DEVICES.lock();
    let Some(index) = devices.iter().position(|entry| Arc::ptr_eq(entry, dev)) else { return false; };
    devices.remove(index);
    true
}

/// Every registered device, newest first. # C: O(N_devices)
pub fn devices() -> Vec<Arc<BacklightDevice>> {
    let mut list: Vec<Arc<BacklightDevice>> = DEVICES.lock().iter().map(Arc::clone).collect();
    list.reverse();
    list
}

/// Resolve one device by name. # C: O(N_devices)
pub fn by_name(name: &str) -> Option<Arc<BacklightDevice>> {
    DEVICES.lock().iter().find(|dev| dev.name() == name).cloned()
}

/// Most recently registered device of `ty`. # C: O(N_devices)
pub fn by_type(ty: BacklightType) -> Option<Arc<BacklightDevice>> {
    devices().into_iter().find(|dev| dev.device_type() == ty)
}

/// Number of registered devices. # C: O(1)
pub fn count() -> usize { DEVICES.lock().len() }

/// Emit a change notification for `dev`. The class always notifies, including
/// after a store that the driver rejected: a consumer's cached level is stale
/// either way and it must re-read. # C: O(1)
pub fn changed(dev: &Arc<BacklightDevice>, reason: UpdateReason) {
    let hook = *CHANGE_HOOK.lock();
    if let Some(hook) = hook { hook(dev.name(), reason.source()); }
}

/// Hotkey path: adopt the level the hardware moved to, then notify. # C: O(driver)
pub fn force_update(dev: &Arc<BacklightDevice>, reason: UpdateReason) {
    dev.adopt_hardware_brightness();
    changed(dev, reason);
}

/// Empty the registry between tests. # C: O(N_devices)
#[cfg(test)]
pub fn clear_for_tests() { DEVICES.lock().clear(); }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Properties;
    use crate::uapi::BACKLIGHT_POWER_ON;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// The class registry is one global object; serialise the tests that
    /// mutate it so a parallel run cannot see another test's devices.
    pub(crate) static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

    static NOTIFICATIONS: AtomicU32 = AtomicU32::new(0);

    fn count_notification(_name: &str, _source: &str) { NOTIFICATIONS.fetch_add(1, Ordering::Relaxed); }

    struct Panel;
    impl BacklightOps for Panel {
        fn update_status(&self, _props: &Properties) -> KResult<()> { Ok(()) }
    }

    fn props(ty: BacklightType) -> Properties {
        Properties { max_brightness: 100, brightness: 50, power: BACKLIGHT_POWER_ON, ty,
                     ..Properties::default() }
    }

    #[test]
    fn a_duplicate_name_is_refused() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        let first = register("acpi_video0", props(BacklightType::Firmware), Arc::new(Panel))
            .expect("first registration");
        assert!(matches!(
            register("acpi_video0", props(BacklightType::Raw), Arc::new(Panel)),
            Err(VfsError::Eexist),
        ));
        assert_eq!(count(), 1);
        assert!(unregister(&first));
        assert_eq!(count(), 0);
        clear_for_tests();
    }

    #[test]
    fn unregistration_detaches_before_it_forgets_the_device() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        let dev = register("bl0", props(BacklightType::Raw), Arc::new(Panel)).expect("register");
        assert!(dev.attached());
        assert!(unregister(&dev));
        assert!(!dev.attached(), "a retained handle must not still reach the driver");
        assert!(!unregister(&dev), "a second unregistration is not a removal");
        assert!(by_name("bl0").is_none());
        clear_for_tests();
    }

    #[test]
    fn lookup_by_type_returns_the_newest_matching_device() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        let _raw = register("raw0", props(BacklightType::Raw), Arc::new(Panel)).expect("raw");
        let _fw = register("fw0", props(BacklightType::Firmware), Arc::new(Panel)).expect("fw");
        let newer_raw = register("raw1", props(BacklightType::Raw), Arc::new(Panel)).expect("raw1");
        assert_eq!(by_type(BacklightType::Raw).map(|d| String::from(d.name())),
                   Some(String::from(newer_raw.name())));
        assert_eq!(by_type(BacklightType::Firmware).map(|d| String::from(d.name())),
                   Some(String::from("fw0")));
        assert_eq!(by_type(BacklightType::Platform).map(|d| String::from(d.name())), None);
        clear_for_tests();
    }

    #[test]
    fn a_registration_notifies_the_installed_hook() {
        let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear_for_tests();
        set_change_hook(count_notification);
        NOTIFICATIONS.store(0, Ordering::Relaxed);
        let dev = register("bl9", props(BacklightType::Raw), Arc::new(Panel)).expect("register");
        assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), 1);
        changed(&dev, UpdateReason::Hotkey);
        assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), 2);
        force_update(&dev, UpdateReason::Hotkey);
        assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), 3);
        assert!(unregister(&dev));
        clear_for_tests();
    }
}
