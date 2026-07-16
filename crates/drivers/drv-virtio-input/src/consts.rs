/// Wire constants per linux/include/uapi/linux/virtio_input.h
/// + virtio 1.2 §5.8.

pub const VIRTIO_ID_INPUT: u16 = 18;
pub(crate) const INPUT_MAJOR: u32 = 13;
pub(crate) const EVENT_MINOR_BASE: u32 = 64;

/// Driver-model identity for virtio-input child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-input", VIRTIO_ID_INPUT);

pub const VIRTIO_INPUT_PCI_DEVICE_ID: u16 = 0x1052;
pub use virtio::resources::VIRTIO_VENDOR_ID as VIRTIO_PCI_VENDOR_RH;

pub const VIRTIO_F_VERSION_1: u32 = 32;
const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;
pub const MAX_INPUT_DEVICES: usize = 8;

pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    #[cfg(target_os = "oxide-kernel")]
    let eventq_irq = Some(crate::drain::raise_drain as fn());
    #[cfg(not(target_os = "oxide-kernel"))]
    let eventq_irq = None;
    virtio::VirtioTransportProfile::q0_device_cfg(wanted_features(), eventq_irq)
}

pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0;
pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 1;
pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 2;
pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 3;
pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;
pub const EV_SW: u16 = 0x05;
pub const EV_LED: u16 = 0x11;
pub const EV_SND: u16 = 0x12;
pub const EV_REP: u16 = 0x14;
pub const EV_FF: u16 = 0x15;
pub const EV_PWR: u16 = 0x16;
pub const EV_FF_STATUS: u16 = 0x17;

pub const SYN_REPORT: u16 = 0x00;
pub const SYN_CONFIG: u16 = 0x01;
pub const SYN_MT_REPORT: u16 = 0x02;
pub const SYN_DROPPED: u16 = 0x03;

pub const EVIOC_GROUP: u8 = b'E';

pub const EVDEV_VERSION: u32 = 0x01_0001;
pub const EVDEV_ID_BYTES: usize = 8;
pub const EVDEV_ID_BUSTYPE_OFF: usize = 0;
pub const EVDEV_ID_VENDOR_OFF: usize = 2;
pub const EVDEV_ID_PRODUCT_OFF: usize = 4;
pub const EVDEV_ID_VERSION_OFF: usize = 6;
pub const EVDEV_ABSINFO_BYTES: usize = 24;
pub const EVDEV_ABSINFO_MIN_OFF: usize = 4;
pub const EVDEV_ABSINFO_MAX_OFF: usize = 8;
pub const EVDEV_ABSINFO_FUZZ_OFF: usize = 12;
pub const EVDEV_ABSINFO_FLAT_OFF: usize = 16;
pub const EVDEV_ABSINFO_RES_OFF: usize = 20;
pub const EVDEV_STR_BYTES: usize = 129;
pub const EVDEV_REPEAT_BYTES: usize = 8;
pub const EVDEV_CLOCKID_BYTES: usize = 4;
pub const EVDEV_FF_EFFECT_BYTES: usize = 44;
pub const EVDEV_CLOCK_MONOTONIC: i32 = 1;

pub const IOC_NR_MASK: u64 = 0xFF;
pub const IOC_TYPE_SHIFT: u32 = 8;
pub const IOC_TYPE_MASK: u64 = 0xFF;
pub const IOC_SIZE_SHIFT: u32 = 16;
pub const IOC_SIZE_MASK: u64 = 0x3FFF;
pub const IOC_DIR_SHIFT: u32 = 30;
pub const IOC_DIR_MASK: u64 = 0x3;
pub const IOC_WRITE: u32 = 1;
pub const IOC_READ: u32 = 2;

pub const EVIOCGVERSION_NR: u8 = 0x01;
pub const EVIOCGID_NR: u8 = 0x02;
pub const EVIOCGVERSION: u64 = 0x80044501;
pub const EVIOCGID: u64 = 0x80084502;
pub const EVIOCREP_NR: u8 = 0x03;
pub const EVIOCGNAME_NR: u8 = 0x06;
pub const EVIOCGUNIQ_NR: u8 = 0x08;
pub const EVIOCGPROP_NR: u8 = 0x09;
pub const EVIOCGKEY_NR: u8 = 0x18;
pub const EVIOCGLED_NR: u8 = 0x19;
pub const EVIOCGSND_NR: u8 = 0x1a;
pub const EVIOCGSW_NR: u8 = 0x1b;
pub const EVIOCGBIT_BASE_NR: u8 = 0x20;
pub const EVIOCGABS_BASE_NR: u8 = 0x40;
pub const EVIOCGABS_END_NR: u8 = 0x80;
pub const EVIOCGREP: u64 = 0x80084503;
pub const EVIOCSREP: u64 = 0x40084503;
pub const EVIOCGPHYS_NR: u8 = 0x07;
pub const EVIOCSFF: u64 = 0x402c4580;
pub const EVIOCRMFF: u64 = 0x40044581;
pub const EVIOCGRAB_NR: u8 = 0x90;
pub const EVIOCGRAB: u64 = 0x40044590;
pub const EVIOCREVOKE_NR: u8 = 0x91;
pub const EVIOCREVOKE: u64 = 0x40044591;
pub const EVIOCSCLOCKID_NR: u8 = 0xa0;
pub const EVIOCSCLOCKID: u64 = 0x400445a0;
pub const EVIOCGEFFECTS: u64 = 0x80044584;

pub const DEFAULT_REP_DELAY_MS: u32 = 250;
pub const DEFAULT_REP_PERIOD_MS: u32 = 33;
pub const DEFAULT_REPEAT: [u32; 2] = [DEFAULT_REP_DELAY_MS, DEFAULT_REP_PERIOD_MS];
