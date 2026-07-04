/// Wire constants per linux/include/uapi/linux/virtio_input.h
/// + virtio 1.2 §5.8.

pub const VIRTIO_ID_INPUT: u16 = 18;

/// Driver-model identity for virtio-input child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-input", VIRTIO_ID_INPUT);

pub const VIRTIO_INPUT_PCI_DEVICE_ID: u16 = 0x1052;
pub const VIRTIO_PCI_VENDOR_RH: u16 = 0x1AF4;

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
pub const EVIOCGREP: u64 = 0x80084503;
pub const EVIOCSREP: u64 = 0x40084503;
pub const EVIOCSFF: u64 = 0x402c4580;
pub const EVIOCRMFF: u64 = 0x40044581;
pub const EVIOCGRAB: u64 = 0x40044590;
pub const EVIOCREVOKE: u64 = 0x40044591;
pub const EVIOCGEFFECTS: u64 = 0x80044584;

pub const DEFAULT_REP_DELAY_MS: u32 = 250;
pub const DEFAULT_REP_PERIOD_MS: u32 = 33;
pub const DEFAULT_REPEAT: [u32; 2] = [DEFAULT_REP_DELAY_MS, DEFAULT_REP_PERIOD_MS];
