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
            let id = (*owned(dev)).evdev_id;
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
            let key = VirtioChildDeviceKey::from_raw((*owned(dev)).oxide_key);
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
            assert!(!(*owned(dev)).registered);
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
