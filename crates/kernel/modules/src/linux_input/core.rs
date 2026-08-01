extern crate alloc;

use super::{convert::*, types::*};
use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicU32, Ordering};
use input::MAX_INPUT_DEVICES;
use input::VirtioChildDeviceKey;

static NEXT_SYNTHETIC_KEY: AtomicU32 = AtomicU32::new(1);

#[cfg(test)]
mod test_constants;

/// Register Linux input KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("input_allocate_device",  input_allocate_device  as *const () as usize, false);
    export("input_free_device",      input_free_device      as *const () as usize, false);
    export("input_register_device",  input_register_device  as *const () as usize, false);
    export("input_unregister_device", input_unregister_device as *const () as usize, false);
    export("input_set_capability",   input_set_capability   as *const () as usize, false);
    export("input_set_abs_params",   input_set_abs_params   as *const () as usize, false);
    export("input_event",            input_event            as *const () as usize, false);
    export("input_report_key",       input_report_key       as *const () as usize, false);
    export("input_report_abs",       input_report_abs       as *const () as usize, false);
    export("input_report_rel",       input_report_rel       as *const () as usize, false);
    export("input_sync",             input_sync             as *const () as usize, false);
    export("input_set_drvdata",      input_set_drvdata      as *const () as usize, false);
    export("input_get_drvdata",      input_get_drvdata      as *const () as usize, false);
}

extern "C" fn input_allocate_device() -> *mut LinuxInputDev {
    let dev = {
        // SAFETY: LinuxInputDev is a C POD mirror; zero initialization matches kzalloc.
        let linux_dev = unsafe { core::mem::zeroed() };
        LinuxInputDev {
            name: null(),
            phys: null(),
            uniq: null(),
            id: LinuxInputId::default(),
            dev: linux_dev,
            private_data: null_mut(),
            propbit: [0; INPUT_PROP_WORDS],
            evbit: [0; INPUT_EV_WORDS],
            keybit: [0; INPUT_KEY_WORDS],
            relbit: [0; INPUT_REL_WORDS],
            absbit: [0; INPUT_ABS_WORDS],
            mscbit: [0; INPUT_MSC_WORDS],
            ledbit: [0; INPUT_LED_WORDS],
            sndbit: [0; INPUT_SND_WORDS],
            ffbit: [0; INPUT_FF_WORDS],
            swbit: [0; INPUT_SW_WORDS],
            absinfo: [LinuxInputAbsInfo::default(); ABS_CNT],
            key: [0; INPUT_KEY_WORDS],
            led: [0; INPUT_LED_WORDS],
            snd: [0; INPUT_SND_WORDS],
            sw: [0; INPUT_SW_WORDS],
            evdev_id: MAX_INPUT_DEVICES as u32,
            registered: 0,
            oxide_key: 0,
        }
    };
    Box::into_raw(Box::new(dev))
}

unsafe extern "C" fn input_free_device(dev: *mut LinuxInputDev) {
    if dev.is_null() { return; }
    // SAFETY: dev was just null-checked, and this KPI entry's contract is that it is an input_allocate_device result the module has not yet freed; registered is an inline u32 of that allocation.
    if unsafe { (*dev).registered } != 0 {
        // SAFETY: unregister_live's precondition is a device that completed input_register_device, which is the only writer of registered != 0 and sets oxide_key/evdev_id before doing so.
        unsafe { unregister_live(dev); }
    }
    // SAFETY: dev was allocated by input_allocate_device and is no longer registered.
    unsafe { drop(Box::from_raw(dev)); }
}

unsafe extern "C" fn input_register_device(dev: *mut LinuxInputDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev was null-checked on the previous line; registering a device the module has already freed is outside this KPI's contract, so the allocation is live and registered readable.
    if unsafe { (*dev).registered } != 0 { return -LINUX_EBUSY; }
    // This KPI does not yet expose input_ff_create()/ff_device callbacks.
    // Reject an incomplete FF device instead of publishing capabilities that
    // EVIOCSFF cannot service.
    // SAFETY: input_register_device validated dev is a live LinuxInputDev pointer.
    if unsafe { test_bit(&(*dev).evbit, EV_FF) } {
        return -LINUX_EINVAL;
    }
    let key = next_device_key();
    // SAFETY: input_register_device exclusively initializes the unregistered device.
    unsafe {
        (*dev).oxide_key = key.raw();
    }
    // SAFETY: input_to_model requires a live LinuxInputDev plus name/phys/uniq that are either null or NUL-terminated; the null test above covers the former and the input KPI requires the module's identity strings to outlive registration. It only copies out of dev, so the &mut aliasing below is unaffected.
    let model = unsafe { input_to_model(dev) };
    let Some((_input_id, evdev_id)) = input::install(model) else {
        // SAFETY: registration still owns the live unregistered LinuxInputDev.
        unsafe { (*dev).oxide_key = 0; }
        return -LINUX_ENOSPC;
    };
    // SAFETY: successful canonical install assigned this device's evdev identity.
    unsafe { (*dev).evdev_id = evdev_id; }
    if !input::publish_evdev(evdev_id) {
        let _ = input::remove_device(key);
        return -LINUX_ENOMEM;
    }
    // SAFETY: dev is the same live allocation validated at fn entry, and install plus publish_evdev have both succeeded, so flipping registered last matches the state unregister_live expects to find.
    unsafe { (*dev).registered = 1; }
    LINUX_OK
}

unsafe extern "C" fn input_unregister_device(dev: *mut LinuxInputDev) {
    if dev.is_null() { return; }
    // SAFETY: dev was just null-checked; per the Linux input KPI it is the input_allocate_device result the module registered, still owned by the module at unregister time.
    if unsafe { (*dev).registered } != 0 {
        // SAFETY: registered != 0 is written only by a completed input_register_device, so the oxide_key and evdev_id that unregister_live tears down are the ones install/publish_evdev handed out.
        unsafe { unregister_live(dev); }
    }
    // SAFETY: Linux input unregister consumes the final device reference from input_allocate_device.
    unsafe { drop(Box::from_raw(dev)); }
}

unsafe extern "C" fn input_set_capability(dev: *mut LinuxInputDev, ev_type: u32, code: u32) {
    if dev.is_null() { return; }
    // SAFETY: dev was null-checked above; the &mut lives only for this call and the input KPI gives the module exclusive ownership of the device until input_register_device, so no other reference to the capability maps exists. set_capability itself range-checks ev_type/code.
    unsafe { set_capability(&mut *dev, ev_type, code); }
}

unsafe extern "C" fn input_set_abs_params(
    dev: *mut LinuxInputDev,
    axis: u16,
    min: i32,
    max: i32,
    fuzz: i32,
    flat: i32,
) {
    if dev.is_null() || axis as usize >= ABS_CNT { return; }
    // SAFETY: dev is non-null per the guard above and the axis guard bounds the index by ABS_CNT, which is exactly the length of the absinfo array; the &mut is transient and the module owns the device exclusively while configuring it.
    unsafe {
        set_capability(&mut *dev, u32::from(EV_ABS), u32::from(axis));
        (*dev).absinfo[axis as usize] = LinuxInputAbsInfo {
            value: 0,
            minimum: min,
            maximum: max,
            fuzz,
            flat,
            resolution: 0,
        };
    }
}

unsafe extern "C" fn input_event(dev: *mut LinuxInputDev, ev_type: u16, code: u16, value: i32) {
    if dev.is_null() { return; }
    // SAFETY: dev was null-checked on the previous line; input_event's KPI contract is that the module reports events only on a device it still owns.
    if unsafe { (*dev).registered } == 0 {
        // SAFETY: same non-null dev; the unregistered branch means no evdev model exists yet, so this &mut to the local state bitmaps is the only live reference. update_state consults the capability bits before touching any array.
        unsafe { update_state(&mut *dev, ev_type, code, value); }
        return;
    }
    // SAFETY: registered != 0, so input_register_device stored the evdev_id that install returned into this still-live device.
    let id = unsafe { (*dev).evdev_id };
    let _ = input::push_evdev_event(id, ev_type, code, value);
}

unsafe extern "C" fn input_report_key(dev: *mut LinuxInputDev, code: u16, value: i32) {
    // SAFETY: input_event's precondition on dev is identical to input_report_key's own, so the caller of this KPI entry has already established it; input_event re-checks for null itself.
    unsafe { input_event(dev, EV_KEY, code, i32::from(value != 0)); }
}

unsafe extern "C" fn input_report_abs(dev: *mut LinuxInputDev, code: u16, value: i32) {
    // SAFETY: forwarding the caller's own dev unchanged to input_event, whose precondition on it is the same one input_report_abs imposes; the null case is handled inside input_event.
    unsafe { input_event(dev, EV_ABS, code, value); }
}

unsafe extern "C" fn input_report_rel(dev: *mut LinuxInputDev, code: u16, value: i32) {
    // SAFETY: forwarding the caller's own dev unchanged to input_event, whose precondition on it is the same one input_report_rel imposes; the null case is handled inside input_event.
    unsafe { input_event(dev, EV_REL, code, value); }
}

unsafe extern "C" fn input_sync(dev: *mut LinuxInputDev) {
    // SAFETY: forwarding the caller's own dev unchanged to input_event, whose precondition on it is the same one input_sync imposes; the null case is handled inside input_event.
    unsafe { input_event(dev, EV_SYN, SYN_REPORT, 0); }
}

unsafe extern "C" fn input_set_drvdata(dev: *mut LinuxInputDev, data: *mut c_void) {
    if dev.is_null() { return; }
    // SAFETY: dev was null-checked above; private_data is an opaque *mut c_void slot the kernel never dereferences, so storing the module's cookie into the live device cannot invalidate anything else.
    unsafe { (*dev).private_data = data; }
}

unsafe extern "C" fn input_get_drvdata(dev: *const LinuxInputDev) -> *mut c_void {
    if dev.is_null() { return null_mut(); }
    // SAFETY: dev was null-checked above; the read returns the opaque cookie by value without dereferencing it, so only the LinuxInputDev allocation itself must be live, which the KPI contract gives.
    unsafe { (*dev).private_data }
}

// Precondition: dev is a live LinuxInputDev whose registered field is non-zero, i.e. input_register_device
// completed and stored the oxide_key/evdev_id read below. No null check here — the two callers do it.
unsafe fn unregister_live(dev: *mut LinuxInputDev) {
    // SAFETY: the precondition above makes dev live and registered, so oxide_key holds the key next_device_key minted for the install that is being torn down.
    let key = VirtioChildDeviceKey::from_raw(unsafe { (*dev).oxide_key });
    // SAFETY: same live registered device; evdev_id is the identity publish_evdev consumed, so unpublish here undoes exactly that publish.
    let _ = input::unpublish_evdev(unsafe { (*dev).evdev_id });
    let _ = input::remove_device(key);
    // SAFETY: dev is still the caller's live allocation — remove_device only dropped the canonical input model, not this KPI mirror — so resetting it to the unregistered state is a plain field write.
    unsafe {
        (*dev).registered = 0;
        (*dev).evdev_id = MAX_INPUT_DEVICES as u32;
        (*dev).oxide_key = 0;
    }
}

fn next_device_key() -> VirtioChildDeviceKey {
    let seq = NEXT_SYNTHETIC_KEY.fetch_add(1, Ordering::Relaxed) & SYNTHETIC_DEVICE_KEY_MASK;
    VirtioChildDeviceKey::from_raw(SYNTHETIC_DEVICE_KEY_BASE | seq)
}

fn capability_code_count(ev_type: u32) -> Option<usize> {
    match ev_type {
        ty if ty == u32::from(EV_KEY) => Some(KEY_CNT),
        ty if ty == u32::from(EV_REL) => Some(REL_CNT),
        ty if ty == u32::from(EV_ABS) => Some(ABS_CNT),
        ty if ty == u32::from(EV_MSC) => Some(MSC_CNT),
        ty if ty == u32::from(EV_SW) => Some(SW_CNT),
        ty if ty == u32::from(EV_LED) => Some(LED_CNT),
        ty if ty == u32::from(EV_SND) => Some(SND_CNT),
        ty if ty == u32::from(EV_FF) => Some(FF_CNT),
        _ => None,
    }
}

fn set_capability(dev: &mut LinuxInputDev, ev_type: u32, code: u32) {
    // Validate type and code before mutating either capability map.
    if ev_type == u32::from(EV_PWR) {
        set_bit(&mut dev.evbit, EV_PWR);
        return;
    }
    let Some(count) = capability_code_count(ev_type) else { return; };
    if code >= count as u32 { return; }
    let ev_type = ev_type as u16;
    let code = code as u16;
    match ev_type {
        EV_KEY => set_bit(&mut dev.keybit, code),
        EV_REL => set_bit(&mut dev.relbit, code),
        EV_ABS => set_bit(&mut dev.absbit, code),
        EV_MSC => set_bit(&mut dev.mscbit, code),
        EV_LED => set_bit(&mut dev.ledbit, code),
        EV_SND => set_bit(&mut dev.sndbit, code),
        EV_FF => set_bit(&mut dev.ffbit, code),
        EV_SW => set_bit(&mut dev.swbit, code),
        _ => return,
    }
    set_bit(&mut dev.evbit, ev_type);
}

fn update_state(dev: &mut LinuxInputDev, ev_type: u16, code: u16, value: i32) {
    let supported = match ev_type {
        EV_KEY => test_bit(&dev.keybit, code),
        EV_ABS => test_bit(&dev.absbit, code),
        EV_SW => test_bit(&dev.swbit, code),
        EV_LED => test_bit(&dev.ledbit, code),
        EV_SND => test_bit(&dev.sndbit, code),
        _ => false,
    };
    if !supported { return; }
    match ev_type {
        EV_KEY if value == 0 => clear_bit(&mut dev.key, code),
        EV_KEY => set_bit(&mut dev.key, code),
        EV_ABS if (code as usize) < ABS_CNT => dev.absinfo[code as usize].value = value,
        EV_SW if value == 0 => clear_bit(&mut dev.sw, code),
        EV_SW => set_bit(&mut dev.sw, code),
        EV_LED if value == 0 => clear_bit(&mut dev.led, code),
        EV_LED => set_bit(&mut dev.led, code),
        EV_SND if value == 0 => clear_bit(&mut dev.snd, code),
        EV_SND => set_bit(&mut dev.snd, code),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_constants::*;
    use core::ffi::c_char;

    fn assert_subtype_capabilities_empty(dev: &LinuxInputDev) {
        assert!(dev.keybit.iter().all(|word| *word == 0));
        assert!(dev.relbit.iter().all(|word| *word == 0));
        assert!(dev.absbit.iter().all(|word| *word == 0));
        assert!(dev.mscbit.iter().all(|word| *word == 0));
        assert!(dev.swbit.iter().all(|word| *word == 0));
        assert!(dev.ledbit.iter().all(|word| *word == 0));
        assert!(dev.sndbit.iter().all(|word| *word == 0));
        assert!(dev.ffbit.iter().all(|word| *word == 0));
    }

    fn assert_capabilities_empty(dev: &LinuxInputDev) {
        assert!(dev.evbit.iter().all(|word| *word == 0));
        assert_subtype_capabilities_empty(dev);
    }

    fn subtype_bit(dev: &LinuxInputDev, ev_type: u16, code: u16) -> bool {
        match ev_type {
            EV_KEY => test_bit(&dev.keybit, code),
            EV_REL => test_bit(&dev.relbit, code),
            EV_ABS => test_bit(&dev.absbit, code),
            EV_MSC => test_bit(&dev.mscbit, code),
            EV_SW => test_bit(&dev.swbit, code),
            EV_LED => test_bit(&dev.ledbit, code),
            EV_SND => test_bit(&dev.sndbit, code),
            EV_FF => test_bit(&dev.ffbit, code),
            _ => false,
        }
    }

    fn model_bit(bits: &[u8], code: u16) -> bool {
        bits[(code / u8::BITS as u16) as usize] & (1 << (code % u8::BITS as u16)) != 0
    }

    #[test]
    fn input_event_abi_is_linux_compatible() {
        let _modules = crate::test_serial::claim();
        assert_eq!(core::mem::size_of::<LinuxInputEvent>(), INPUT_EVENT_BYTES);
    }

    #[test]
    fn input_device_mirror_matches_kpi_header_layout() {
        let _modules = crate::test_serial::claim();
        assert_eq!(core::mem::size_of::<LinuxInputDev>(), INPUT_DEV_ABI_BYTES);
        assert_eq!(core::mem::offset_of!(LinuxInputDev, propbit), PROPBIT_OFFSET);
        assert_eq!(core::mem::offset_of!(LinuxInputDev, mscbit), MSCBIT_OFFSET);
        assert_eq!(core::mem::offset_of!(LinuxInputDev, sndbit), SNDBIT_OFFSET);
        assert_eq!(core::mem::offset_of!(LinuxInputDev, ffbit), FFBIT_OFFSET);
        assert_eq!(core::mem::offset_of!(LinuxInputDev, swbit), SWBIT_OFFSET);
        assert_eq!(core::mem::offset_of!(LinuxInputDev, absinfo), ABSINFO_OFFSET);
        assert_eq!(core::mem::offset_of!(LinuxInputDev, snd), SND_STATE_OFFSET);
        assert_eq!(core::mem::offset_of!(LinuxInputDev, sw), SW_STATE_OFFSET);
    }

    #[test]
    fn register_exports_capabilities_to_evdev_model() {
        let _modules = crate::test_serial::claim();
        let dev = input_allocate_device();
        assert!(!dev.is_null());
        // SAFETY: dev is the uniquely owned allocation just returned by input_allocate_device and asserted non-null; NAME/PHYS are NUL-terminated statics that outlive the registration, satisfying the string-lifetime half of the KPI contract, and input_unregister_device at the end of the block consumes the box exactly once.
        unsafe {
            (*dev).name = NAME.as_ptr() as *const c_char;
            (*dev).phys = PHYS.as_ptr() as *const c_char;
            (*dev).id.bustype = TEST_BUS;
            (*dev).id.vendor = input::VIRTIO_PCI_VENDOR_ID;
            (*dev).id.product = TEST_PRODUCT;
            input_set_capability(dev, u32::from(EV_KEY), u32::from(KEY_A));
            input_set_capability(dev, u32::from(EV_MSC), u32::from(MSC_SCAN));
            input_set_capability(dev, u32::from(EV_LED), u32::from(LED_NUML));
            input_set_capability(dev, u32::from(EV_SND), u32::from(SND_BELL));
            input_set_capability(dev, u32::from(EV_SW), u32::from(SW_LID));
            input_set_abs_params(
                dev, ABS_X, ABS_MINIMUM, ABS_MAXIMUM, ABS_FUZZ, ABS_FLAT,
            );
            input_report_key(dev, KEY_A, STATE_ACTIVE);
            input_event(dev, EV_LED, LED_NUML, STATE_ACTIVE);
            input_event(dev, EV_SND, SND_BELL, STATE_ACTIVE);
            input_event(dev, EV_SW, SW_LID, STATE_ACTIVE);
            assert_eq!(input_register_device(dev), LINUX_OK);
            let id = (*dev).evdev_id;
            let model = input::device(id).expect("registered input model");
            assert_eq!(model.name_len, NAME.len() - 1);
            assert_eq!(&model.name[..model.name_len], &NAME[..NAME.len() - 1]);
            assert_eq!(model.phys_len, PHYS.len() - 1);
            assert_eq!(&model.phys[..model.phys_len], &PHYS[..PHYS.len() - 1]);
            assert!(model.is_pointer);
            assert!(model_bit(&model.key_bits.bits, KEY_A));
            assert!(model_bit(&model.msc_bits.bits, MSC_SCAN));
            assert!(model_bit(&model.led_bits.bits, LED_NUML));
            assert!(model_bit(&model.snd_bits.bits, SND_BELL));
            assert!(!model_bit(&model.ff_bits.bits, FF_RUMBLE));
            assert!(model_bit(&model.sw_bits.bits, SW_LID));
            assert!(model.abs_info[ABS_X as usize].is_some());
            assert!(model_bit(model.state_bits(EV_KEY).expect("key state"), KEY_A));
            assert_ne!(
                model.state_bits(EV_LED).expect("led state")[0] & (1u8 << LED_NUML),
                0,
            );
            assert_ne!(
                model.state_bits(EV_SND).expect("sound state")[0] & (1u8 << SND_BELL),
                0,
            );
            assert_ne!(
                model.state_bits(EV_SW).expect("switch state")[0] & (1u8 << SW_LID),
                0,
            );
            input_report_key(dev, KEY_A, STATE_INACTIVE);
            input_event(dev, EV_LED, LED_NUML, STATE_INACTIVE);
            let model = input::device(id).expect("live input state");
            assert!(!model_bit(model.state_bits(EV_KEY).expect("key state"), KEY_A));
            assert_eq!(
                model.state_bits(EV_LED).expect("led state")[0] & (1u8 << LED_NUML),
                0,
            );
            let key = VirtioChildDeviceKey::from_raw((*dev).oxide_key);
            assert!(
                input::set_inhibited_by_identity(key, model.input_id, id, true).is_some(),
            );
            input_report_key(dev, KEY_A, STATE_ACTIVE);
            let model = input::device(id).expect("inhibited input state");
            assert!(!model_bit(model.state_bits(EV_KEY).expect("key state"), KEY_A));
            input_unregister_device(dev);
            assert!(input::device(id).is_none());
        }
    }

    #[test]
    fn register_rejects_force_feedback_without_ff_backend() {
        let _modules = crate::test_serial::claim();
        let dev = input_allocate_device();
        assert!(!dev.is_null());
        // SAFETY: dev is the uniquely owned allocation just returned by input_allocate_device and asserted non-null; NAME is a NUL-terminated static, registration is expected to fail so nothing is published, and input_free_device consumes the box exactly once.
        unsafe {
            (*dev).name = NAME.as_ptr() as *const c_char;
            input_set_capability(dev, u32::from(EV_FF), u32::from(FF_RUMBLE));
            assert_eq!(input_register_device(dev), -LINUX_EINVAL);
            assert_eq!((*dev).registered, 0);
            input_free_device(dev);
        }
    }

    #[test]
    fn input_set_capability_rejects_invalid_codes_without_partial_mutation() {
        let _modules = crate::test_serial::claim();
        let invalid = [
            (EV_KEY, KEY_CNT),
            (EV_REL, REL_CNT),
            (EV_ABS, ABS_CNT),
            (EV_MSC, MSC_CNT),
            (EV_SW, SW_CNT),
            (EV_LED, LED_CNT),
            (EV_SND, SND_CNT),
            (EV_FF, FF_CNT),
        ];
        for (ev_type, count) in invalid {
            let dev = input_allocate_device();
            assert!(!dev.is_null());
            // SAFETY: input_allocate_device returned this uniquely owned live object.
            unsafe {
                input_set_capability(dev, u32::from(ev_type), count as u32);
                assert_capabilities_empty(&*dev);
                input_free_device(dev);
            }
        }
    }

    #[test]
    fn input_set_capability_rejects_unknown_or_truncated_aliases() {
        let _modules = crate::test_serial::claim();
        let dev = input_allocate_device();
        assert!(!dev.is_null());
        // SAFETY: input_allocate_device returned this uniquely owned live object.
        unsafe {
            input_set_capability(dev, UNKNOWN_EVENT_TYPE, 0);
            input_set_capability(
                dev,
                u32::from(EV_KEY) | WIDE_ALIAS_BIT,
                u32::from(KEY_A),
            );
            input_set_capability(
                dev,
                u32::from(EV_KEY),
                u32::from(KEY_A) | WIDE_ALIAS_BIT,
            );
            assert_capabilities_empty(&*dev);
            input_free_device(dev);
        }
    }

    #[test]
    fn input_set_capability_accepts_linux_max_codes() {
        let _modules = crate::test_serial::claim();
        let dev = input_allocate_device();
        assert!(!dev.is_null());
        let valid = [
            (EV_KEY, KEY_CNT),
            (EV_REL, REL_CNT),
            (EV_ABS, ABS_CNT),
            (EV_MSC, MSC_CNT),
            (EV_SW, SW_CNT),
            (EV_LED, LED_CNT),
            (EV_SND, SND_CNT),
            (EV_FF, FF_CNT),
        ];
        // SAFETY: input_allocate_device returned this uniquely owned live object.
        unsafe {
            for (ev_type, count) in valid {
                input_set_capability(dev, u32::from(ev_type), count as u32 - 1);
                assert!(test_bit(&(*dev).evbit, ev_type));
                assert!(subtype_bit(&*dev, ev_type, (count - 1) as u16));
            }
            input_free_device(dev);
        }
    }

    #[test]
    fn input_set_capability_accepts_power_without_subtype_mutation() {
        let _modules = crate::test_serial::claim();
        let dev = input_allocate_device();
        assert!(!dev.is_null());
        // SAFETY: input_allocate_device returned this uniquely owned live object.
        unsafe {
            input_set_capability(dev, u32::from(EV_PWR), u32::MAX);
            assert!(test_bit(&(*dev).evbit, EV_PWR));
            assert_subtype_capabilities_empty(&*dev);
            input_free_device(dev);
        }
    }
}
