//! LED class registration bridges native LED objects into device core.

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_char;
use sync::{Modules as ModulesLockClass, Spinlock};

use crate::linux_device::types::LinuxDevice;

const LED_DEV_OFFSET: usize = 80;
const LED_MAX_BRIGHTNESS_OFFSET: usize = 12;
const LED_NAME_OFFSET: usize = 0;
const LED_DEFAULT_BRIGHTNESS: u32 = 255;

static LEDS: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());

/// Register LED class entry points required by native PCI drivers.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    export("led_classdev_register_ext", led_classdev_register_ext as *const () as usize, true);
    export("led_classdev_unregister", led_classdev_unregister as *const () as usize, true);
}

extern "C" fn led_classdev_register_ext(parent: *mut LinuxDevice, led: *mut u8, _init: *const u8) -> i32 {
    if led.is_null() { return -22; }
    // SAFETY: native led_classdev ABI begins with its C-string name pointer.
    let name = unsafe { led.add(LED_NAME_OFFSET).cast::<*const c_char>().read_unaligned() };
    let dev = crate::linux_device::core::register_child(parent, name);
    if dev.is_null() { return -12; }
    // SAFETY: native led_classdev ABI places max_brightness at 12 and its device pointer at 80.
    unsafe {
        let max = led.add(LED_MAX_BRIGHTNESS_OFFSET).cast::<u32>();
        if max.read_unaligned() == 0 { max.write_unaligned(LED_DEFAULT_BRIGHTNESS); }
        led.add(LED_DEV_OFFSET).cast::<*mut LinuxDevice>().write_unaligned(dev);
    }
    LEDS.lock().push(led as usize);
    0
}

extern "C" fn led_classdev_unregister(led: *mut u8) {
    if led.is_null() { return; }
    let found = {
        let mut leds = LEDS.lock();
        let Some(index) = leds.iter().position(|entry| *entry == led as usize) else { return; };
        leds.swap_remove(index);
        true
    };
    if !found { return; }
    // SAFETY: registration initialized the native led_classdev device-pointer field at this fixed ABI offset.
    let dev = unsafe { led.add(LED_DEV_OFFSET).cast::<*mut LinuxDevice>().read_unaligned() };
    crate::linux_device::core::unregister_child(dev);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    #[test]
    fn register_creates_and_unregisters_a_device_core_child() {
        let _modules = crate::test_serial::claim();
        let mut led = [0u8; 432];
        let name = b"nic\0";
        // SAFETY: the test buffer models the native name-pointer field at offset zero.
        unsafe { led.as_mut_ptr().cast::<*const c_char>().write_unaligned(name.as_ptr().cast()); }
        assert_eq!(led_classdev_register_ext(null_mut(), led.as_mut_ptr(), core::ptr::null()), 0);
        // SAFETY: test array provides the documented native led class-device prefix and registration filled dev.
        assert!(!unsafe { led.as_ptr().add(LED_DEV_OFFSET).cast::<*mut LinuxDevice>().read_unaligned() }.is_null());
        // SAFETY: same 432-byte test buffer registration initialized above; LED_MAX_BRIGHTNESS_OFFSET is the native led_classdev's fixed max_brightness field offset this module's ABI layout assumes.
        assert_eq!(unsafe { led.as_ptr().add(LED_MAX_BRIGHTNESS_OFFSET).cast::<u32>().read_unaligned() }, LED_DEFAULT_BRIGHTNESS);
        led_classdev_unregister(led.as_mut_ptr());
    }
}
