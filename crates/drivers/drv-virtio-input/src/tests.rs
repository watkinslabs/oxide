use crate::{
    count, device, evdev_id_for_device, install, remove_device,
    VirtioInputAbsInfo, VirtioInputDev, VirtioInputDevIds, VirtioInputEvent, DEFAULT_REPEAT,
    EV_ABS, EV_FF, EV_KEY, EV_LED, EV_MSC, EV_REL, EV_REP, EV_SND, EV_SW,
    VIRTIO_INPUT_CFG_ABS_INFO, VIRTIO_INPUT_CFG_EV_BITS, VIRTIO_INPUT_CFG_ID_DEVIDS,
    VIRTIO_INPUT_CFG_ID_NAME, VIRTIO_INPUT_CFG_ID_SERIAL, VIRTIO_INPUT_CFG_PROP_BITS,
};

use crate::registry::InputConfigAccess;

const TEST_DEVICE_KEY_RAW: u32 = 0x0010_0000;
const SECOND_TEST_DEVICE_KEY_RAW: u32 = 0x0020_0000;
const TEST_NAME: &[u8] = b"oxide keyboard";
const TEST_SERIAL: &[u8] = b"input-serial";
const TEST_BUS_TYPE: u16 = 0x0003;
const TEST_VENDOR: u16 = 0x1234;
const TEST_PRODUCT: u16 = 0x5678;
const TEST_VERSION: u16 = 0x9abc;
const TEST_PROP_POINTER_BIT: u16 = 1;
const TEST_KEY_CAP_BIT: u16 = 30;
const TEST_REL_AXIS: u16 = 1;
const TEST_ABS_AXIS: u16 = 0;
const TEST_MSC_CAP_BIT: u16 = 4;
const TEST_LED_CAP_BIT: u16 = 2;
const TEST_SND_CAP_BIT: u16 = 3;
const TEST_FF_CAP_BIT: u16 = 5;
const TEST_SW_CAP_BIT: u16 = 6;
const TEST_ABS_MIN: u32 = 1;
const TEST_ABS_MAX: u32 = 2;
const TEST_ABS_FUZZ: u32 = 3;
const TEST_ABS_FLAT: u32 = 4;
const TEST_ABS_RES: u32 = 5;
const TEST_BYTE_BITS: u16 = 8;
const TEST_REPEAT_SETTINGS: input::RepeatSettings = [400, 40];
const TEST_TRANSPORT_VENDOR: u16 = 0x1af4;
const TEST_VIRTIO_INPUT_DEVICE_ID: u16 = 18;

fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn test_dev(device_key: virtio::VirtioChildDeviceKey) -> VirtioInputDev {
    VirtioInputDev::empty(device_key)
}

// `crate::registry` is a process-global device table: these tests call
// `clear_devices_for_tests()` then assert exact `count()`/lookup results, so
// one test's clear lands inside another's measurement window.
static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn event_layout() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputEvent>(), 8);
}

#[test]
fn absinfo_layout() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputAbsInfo>(), 20);
}

#[test]
fn devids_layout() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputDevIds>(), 8);
}

#[test]
fn transport_profile_carries_child_feature_mask() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let profile = crate::transport_profile();

    assert_eq!(profile.drv_features, crate::wanted_features());
    assert_eq!(profile.drv_features, virtio::VIRTIO_F_VERSION_1);
    assert!(profile.child_requirements.needs_device_cfg);
    assert!(profile.child_requirements.required_queues[0]);
    assert!(profile.child_requirements.required_queues[1]);
    assert!(profile.child_requirements.required_queues[2..].iter().all(|required| !required));
}

#[test]
fn install_count_roundtrip() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    assert_eq!(count(), 0);
    install(test_dev(key(0))).expect("install test model");
    assert_eq!(count(), 1);
    crate::registry::clear_devices_for_tests();
}

#[test]
fn lookup_and_remove_use_typed_child_key() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    let (_, first_id) =
        install(test_dev(key(TEST_DEVICE_KEY_RAW))).expect("install first model");
    let (_, second_id) =
        install(test_dev(key(SECOND_TEST_DEVICE_KEY_RAW))).expect("install second model");

    assert_eq!(evdev_id_for_device(key(TEST_DEVICE_KEY_RAW)), Some(first_id));
    assert_eq!(remove_device(key(TEST_DEVICE_KEY_RAW)), Some(first_id));
    assert_eq!(evdev_id_for_device(key(TEST_DEVICE_KEY_RAW)), None);
    assert_eq!(
        evdev_id_for_device(key(SECOND_TEST_DEVICE_KEY_RAW)),
        Some(second_id),
    );

    crate::registry::clear_devices_for_tests();
}

#[test]
fn multiple_input_records_remain_independent() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    let keyboard = key(TEST_DEVICE_KEY_RAW);
    let pointer = key(SECOND_TEST_DEVICE_KEY_RAW);

    let (_, keyboard_id) = install(test_dev(keyboard)).expect("install keyboard");
    let (_, pointer_id) = install(test_dev(pointer)).expect("install pointer");

    let devices = crate::devices_snapshot();
    assert_eq!(devices.len(), 2);
    assert_eq!(evdev_id_for_device(keyboard), Some(keyboard_id));
    assert_eq!(evdev_id_for_device(pointer), Some(pointer_id));
    assert_eq!(remove_device(keyboard), Some(keyboard_id));
    assert_eq!(evdev_id_for_device(pointer), Some(pointer_id));
    assert_eq!(count(), 1);

    crate::registry::clear_devices_for_tests();
}

#[test]
fn repeat_state_is_keyed_by_evdev_device() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    let device_key = key(TEST_DEVICE_KEY_RAW);
    let (input_id, evdev_id) = install(test_dev(device_key)).expect("install repeat model");
    assert_eq!(
        input::repeat_by_identity(device_key, input_id, evdev_id),
        Some(DEFAULT_REPEAT),
    );
    assert!(input::set_repeat_by_identity(
        device_key,
        input_id,
        evdev_id,
        TEST_REPEAT_SETTINGS,
    ));
    assert_eq!(
        input::repeat_by_identity(device_key, input_id, evdev_id),
        Some(TEST_REPEAT_SETTINGS),
    );
    crate::registry::clear_devices_for_tests();
}

struct FakeInputConfig {
    select: u8,
    subsel: u8,
    selections: alloc::vec::Vec<(u8, u8)>,
    name: [u8; 128],
    name_len: usize,
    serial: [u8; 128],
    serial_len: usize,
    ids: [u8; 8],
    ids_len: usize,
    prop_bits: [u8; 4],
    key_bits: [u8; 96],
    rel_bits: [u8; 96],
    abs_bits: [u8; 96],
    msc_bits: [u8; 96],
    led_bits: [u8; 96],
    snd_bits: [u8; 96],
    ff_bits: [u8; 96],
    sw_bits: [u8; 96],
    abs_info: [u8; 20],
}

impl FakeInputConfig {
    fn new() -> Self {
        let mut cfg = Self {
            select: 0,
            subsel: 0,
            selections: alloc::vec::Vec::new(),
            name: [0; 128],
            name_len: TEST_NAME.len(),
            serial: [0; 128],
            serial_len: TEST_SERIAL.len(),
            ids: [0; 8],
            ids_len: 8,
            prop_bits: [0; 4],
            key_bits: [0; 96],
            rel_bits: [0; 96],
            abs_bits: [0; 96],
            msc_bits: [0; 96],
            led_bits: [0; 96],
            snd_bits: [0; 96],
            ff_bits: [0; 96],
            sw_bits: [0; 96],
            abs_info: [0; 20],
        };
        cfg.name[..TEST_NAME.len()].copy_from_slice(TEST_NAME);
        cfg.serial[..TEST_SERIAL.len()].copy_from_slice(TEST_SERIAL);
        cfg.ids = [
            TEST_BUS_TYPE as u8, (TEST_BUS_TYPE >> TEST_BYTE_BITS) as u8,
            TEST_VENDOR as u8, (TEST_VENDOR >> TEST_BYTE_BITS) as u8,
            TEST_PRODUCT as u8, (TEST_PRODUCT >> TEST_BYTE_BITS) as u8,
            TEST_VERSION as u8, (TEST_VERSION >> TEST_BYTE_BITS) as u8,
        ];
        set_test_bit(&mut cfg.prop_bits, TEST_PROP_POINTER_BIT);
        set_test_bit(&mut cfg.key_bits, TEST_KEY_CAP_BIT);
        set_test_bit(&mut cfg.rel_bits, TEST_REL_AXIS);
        set_test_bit(&mut cfg.abs_bits, TEST_ABS_AXIS);
        set_test_bit(&mut cfg.msc_bits, TEST_MSC_CAP_BIT);
        set_test_bit(&mut cfg.led_bits, TEST_LED_CAP_BIT);
        set_test_bit(&mut cfg.snd_bits, TEST_SND_CAP_BIT);
        set_test_bit(&mut cfg.ff_bits, TEST_FF_CAP_BIT);
        set_test_bit(&mut cfg.sw_bits, TEST_SW_CAP_BIT);
        cfg.abs_info = [
            TEST_ABS_MIN as u8, 0, 0, 0,
            TEST_ABS_MAX as u8, 0, 0, 0,
            TEST_ABS_FUZZ as u8, 0, 0, 0,
            TEST_ABS_FLAT as u8, 0, 0, 0,
            TEST_ABS_RES as u8, 0, 0, 0,
        ];
        cfg
    }

    fn selected_payload(&self) -> (&[u8], u8) {
        match (self.select, self.subsel) {
            (VIRTIO_INPUT_CFG_ID_NAME, 0) => (&self.name, self.name_len as u8),
            (VIRTIO_INPUT_CFG_ID_SERIAL, 0) => (&self.serial, self.serial_len as u8),
            (VIRTIO_INPUT_CFG_ID_DEVIDS, 0) => (&self.ids, self.ids_len as u8),
            (VIRTIO_INPUT_CFG_PROP_BITS, 0) => (&self.prop_bits, self.prop_bits.len() as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, x) if x == EV_KEY as u8 => (&self.key_bits, self.key_bits.len() as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, x) if x == EV_REL as u8 => (&self.rel_bits, self.rel_bits.len() as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, x) if x == EV_ABS as u8 => (&self.abs_bits, self.abs_bits.len() as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, x) if x == EV_MSC as u8 => (&self.msc_bits, self.msc_bits.len() as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, x) if x == EV_LED as u8 => (&self.led_bits, self.led_bits.len() as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, x) if x == EV_SND as u8 => (&self.snd_bits, self.snd_bits.len() as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, x) if x == EV_FF as u8 => (&self.ff_bits, self.ff_bits.len() as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, x) if x == EV_SW as u8 => (&self.sw_bits, self.sw_bits.len() as u8),
            (VIRTIO_INPUT_CFG_ABS_INFO, 0) => (&self.abs_info, self.abs_info.len() as u8),
            _ => (&[], 0),
        }
    }
}

impl InputConfigAccess for FakeInputConfig {
    fn select(&mut self, select: u8, subsel: u8) -> u8 {
        self.select = select;
        self.subsel = subsel;
        self.selections.push((select, subsel));
        self.selected_payload().1
    }

    fn payload(&mut self, dst: &mut [u8]) -> usize {
        let (payload, size) = self.selected_payload();
        let n = (size as usize).min(dst.len());
        dst[..n].copy_from_slice(&payload[..n]);
        n
    }

    fn payload_u8(&mut self, off: u64) -> u8 {
        let (payload, size) = self.selected_payload();
        let idx = off as usize;
        if idx < size as usize { payload[idx] } else { 0 }
    }
}

fn set_test_bit(bits: &mut [u8], bit: u16) {
    bits[(bit / TEST_BYTE_BITS) as usize] |= 1u8 << (bit % TEST_BYTE_BITS);
}

fn test_bit(bits: &[u8], bit: u16) -> bool {
    (bits[(bit / TEST_BYTE_BITS) as usize] & (1u8 << (bit % TEST_BYTE_BITS))) != 0
}

#[test]
fn install_device_reads_identity_and_caps_from_generic_config() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    let mut cfg = FakeInputConfig::new();
    let evdev_id = crate::registry::install_device_with_config_for_tests(key(TEST_DEVICE_KEY_RAW), &mut cfg)
        .expect("fake config should install input device");
    let dev = device(evdev_id).expect("installed device is visible");

    assert_eq!(&dev.name[..dev.name_len], TEST_NAME);
    assert_eq!(&dev.serial[..dev.serial_len], TEST_SERIAL);
    assert_eq!(dev.ids.bustype, TEST_BUS_TYPE);
    assert_eq!(dev.ids.vendor, TEST_VENDOR);
    assert_eq!(dev.ids.product, TEST_PRODUCT);
    assert_eq!(dev.ids.version, TEST_VERSION);
    assert!(test_bit(&dev.prop_bits, TEST_PROP_POINTER_BIT));
    assert!(test_bit(&dev.ev_bits, EV_KEY));
    assert!(test_bit(&dev.ev_bits, EV_REL));
    assert!(test_bit(&dev.ev_bits, EV_ABS));
    assert!(test_bit(&dev.ev_bits, EV_MSC));
    assert!(test_bit(&dev.ev_bits, EV_LED));
    assert!(test_bit(&dev.ev_bits, EV_SND));
    assert!(!test_bit(&dev.ev_bits, EV_FF));
    assert!(test_bit(&dev.ev_bits, EV_SW));
    assert!(test_bit(&dev.key_bits.bits, TEST_KEY_CAP_BIT));
    assert!(test_bit(&dev.rel_bits.bits, TEST_REL_AXIS));
    assert!(test_bit(&dev.abs_bits.bits, TEST_ABS_AXIS));
    assert!(test_bit(&dev.msc_bits.bits, TEST_MSC_CAP_BIT));
    assert!(test_bit(&dev.led_bits.bits, TEST_LED_CAP_BIT));
    assert!(test_bit(&dev.snd_bits.bits, TEST_SND_CAP_BIT));
    assert!(!test_bit(&dev.ff_bits.bits, TEST_FF_CAP_BIT));
    assert!(test_bit(&dev.sw_bits.bits, TEST_SW_CAP_BIT));
    assert_eq!(dev.abs_info[TEST_ABS_AXIS as usize].map(|info| (info.min, info.max, info.fuzz, info.flat, info.res)), Some((TEST_ABS_MIN, TEST_ABS_MAX, TEST_ABS_FUZZ, TEST_ABS_FLAT, TEST_ABS_RES)));
    assert!(dev.is_pointer);
    assert_eq!(
        cfg.selections,
        alloc::vec![
            (VIRTIO_INPUT_CFG_ID_NAME, 0),
            (VIRTIO_INPUT_CFG_ID_SERIAL, 0),
            (VIRTIO_INPUT_CFG_ID_DEVIDS, 0),
            (VIRTIO_INPUT_CFG_PROP_BITS, 0),
            (VIRTIO_INPUT_CFG_EV_BITS, EV_KEY as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, EV_REL as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, EV_ABS as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, EV_MSC as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, EV_SW as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, EV_LED as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, EV_SND as u8),
            (VIRTIO_INPUT_CFG_EV_BITS, EV_REP as u8),
            (VIRTIO_INPUT_CFG_ABS_INFO, TEST_ABS_AXIS as u8),
        ],
        "virtio probes exactly the Linux-supported selectors",
    );

    crate::registry::clear_devices_for_tests();
}

#[test]
fn short_devids_uses_linux_bus_virtual_fallback() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    let mut cfg = FakeInputConfig::new();
    cfg.ids_len = 4;
    let evdev_id = crate::registry::install_device_with_config_for_tests(
        key(TEST_DEVICE_KEY_RAW + 1),
        &mut cfg,
    ).expect("short DEVIDS input installs");
    let dev = device(evdev_id).expect("short DEVIDS model");
    assert_eq!(dev.ids.bustype, crate::registry::BUS_VIRTUAL);
    assert_eq!(dev.ids.vendor, 0);
    assert_eq!(dev.ids.product, 0);
    assert_eq!(dev.ids.version, 0);
    crate::registry::clear_devices_for_tests();
}

#[test]
fn prepared_device_is_published_only_after_explicit_commit() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    let mut cfg = FakeInputConfig::new();
    let parent_addr = alloc::string::String::from("virtio0");
    let parent = alloc::sync::Arc::new(drv::Device::new(
        "virtio",
        parent_addr.clone(),
        TEST_TRANSPORT_VENDOR,
        TEST_VIRTIO_INPUT_DEVICE_ID,
        0,
    ));
    drv::try_device_add(alloc::sync::Arc::clone(&parent))
        .expect("virtio parent registration");
    let evdev_id = crate::registry::prepare_device_with_config_and_parent_for_tests(
        key(TEST_DEVICE_KEY_RAW),
        &mut cfg,
        Some(&parent),
    )
    .expect("canonical input preparation succeeds");
    assert!(drv::devices().iter().all(|device| {
        !(device.bus == "input" && device.addr == alloc::format!("event{evdev_id}"))
    }));
    assert!(crate::publish_device_node(evdev_id, Some(&parent)));
    let dev = drv::devices()
        .into_iter()
        .find(|d| d.bus == "input" && d.addr == alloc::format!("event{evdev_id}"))
        .expect("event node published through driver core");

    assert_eq!(dev.parent(), Some(("virtio", parent_addr.as_str())));
    let model = device(evdev_id).expect("canonical input model");
    assert_eq!(&model.phys[..model.phys_len], b"virtio0/input0");
    assert_eq!(
        drv::device_canon_exact(&dev),
        Some(alloc::format!(
            "devices/virtio/virtio0/input/input{}/event{evdev_id}",
            model.input_id,
        )),
    );
    assert!(dev.uevent_env.is_empty());
    let env = input::uevent_env(evdev_id);
    assert!(env.iter().any(|entry| entry.as_slice() == b"PRODUCT=3/1234/5678/9abc"));
    assert!(env.iter().any(|entry| entry.as_slice() == b"NAME=\"oxide keyboard\""));
    assert!(env.iter().any(|entry| entry.as_slice() == b"PHYS=\"virtio0/input0\""));
    assert!(env.iter().any(|entry| entry.as_slice() == b"UNIQ=\"input-serial\""));
    assert!(env.iter().any(|entry| entry.as_slice() == b"PROP=2"));
    assert!(env.iter().any(|entry| entry.as_slice() == b"EV=6003f"));
    assert!(env.iter().any(|entry| entry.as_slice() == b"KEY=40000000"));
    assert!(env.iter().any(|entry| entry.as_slice() == b"REL=2"));
    assert!(env.iter().any(|entry| entry.as_slice() == b"ABS=1"));
    assert!(env.iter().any(|entry| entry.as_slice() == b"MSC=10"));
    assert!(env.iter().any(|entry| entry.as_slice() == b"LED=4"));
    assert!(env.iter().any(|entry| entry.as_slice() == b"SND=8"));
    assert!(!env.iter().any(|entry| entry.starts_with(b"FF=")));
    assert!(env.iter().any(|entry| entry.as_slice() == b"SW=40"));
    assert!(env.iter().any(|entry| entry.starts_with(b"MODALIAS=input:")));
    assert_eq!(evdev_id_for_device(key(TEST_DEVICE_KEY_RAW)), Some(evdev_id));
    assert_eq!(crate::remove_device_with_node(key(TEST_DEVICE_KEY_RAW)), Some(evdev_id));
    assert_eq!(evdev_id_for_device(key(TEST_DEVICE_KEY_RAW)), None);
    assert!(
        drv::devices()
            .iter()
            .all(|d| !(d.bus == "input" && d.addr == alloc::format!("event{evdev_id}")))
    );
    drv::device_del(&parent);

    crate::registry::clear_devices_for_tests();
}
