// virtio-input driver per docs/46. Owns wire protocol (EVENTQ +
// STATUSQ ring service), config-space probe, and the bridge to
// Linux's input_event ABI for /dev/input/event<N> evdev clients.
// Consumed by `50` (VT) for keyboard input.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as DriverLockClass};

// ============================================================
// Wire constants per linux/include/uapi/linux/virtio_input.h
// + virtio 1.2 §5.8
// ============================================================

pub const VIRTIO_ID_INPUT: u16 = 18;

pub const VIRTIO_INPUT_PCI_DEVICE_ID: u16 = 0x1052;
pub const VIRTIO_PCI_VENDOR_RH:       u16 = 0x1AF4;

pub const VIRTIO_F_VERSION_1: u32 = 32;

// virtio_input_config.select selectors
pub const VIRTIO_INPUT_CFG_UNSET:     u8 = 0;
pub const VIRTIO_INPUT_CFG_ID_NAME:   u8 = 1;
pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 2;
pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 3;
pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
pub const VIRTIO_INPUT_CFG_EV_BITS:   u8 = 0x11;
pub const VIRTIO_INPUT_CFG_ABS_INFO:  u8 = 0x12;

// EV_* type codes per linux/include/uapi/linux/input-event-codes.h
pub const EV_SYN:    u16 = 0x00;
pub const EV_KEY:    u16 = 0x01;
pub const EV_REL:    u16 = 0x02;
pub const EV_ABS:    u16 = 0x03;
pub const EV_MSC:    u16 = 0x04;
pub const EV_SW:     u16 = 0x05;
pub const EV_LED:    u16 = 0x11;
pub const EV_SND:    u16 = 0x12;
pub const EV_REP:    u16 = 0x14;
pub const EV_FF:     u16 = 0x15;
pub const EV_PWR:    u16 = 0x16;
pub const EV_FF_STATUS: u16 = 0x17;

// SYN_REPORT and friends
pub const SYN_REPORT:    u16 = 0x00;
pub const SYN_CONFIG:    u16 = 0x01;
pub const SYN_MT_REPORT: u16 = 0x02;
pub const SYN_DROPPED:   u16 = 0x03;

// EVIOC* ioctls — bases. The full _IOR/_IOW encoding lives at the
// VFS dispatch site; these are the cmd-nr + group letter values
// used for matching.
pub const EVIOC_GROUP: u8 = b'E';

pub const EVIOCGVERSION: u64 = 0x80044501;
pub const EVIOCGID:      u64 = 0x80084502;
// Variable-len ioctls match by group + nr only:
pub const EVIOCGNAME_NR: u8 = 0x06;
pub const EVIOCGUNIQ_NR: u8 = 0x08;
pub const EVIOCGPROP_NR: u8 = 0x09;
pub const EVIOCGKEY_NR:  u8 = 0x18;
pub const EVIOCGLED_NR:  u8 = 0x19;
pub const EVIOCGSND_NR:  u8 = 0x1a;
pub const EVIOCGSW_NR:   u8 = 0x1b;
// EVIOCGBIT(ev, len) → nr = 0x20 + ev (ev in 0..0x1f).
pub const EVIOCGBIT_BASE_NR: u8 = 0x20;
// EVIOCGABS(axis)   → nr = 0x40 + axis (axis in 0..0x3f).
pub const EVIOCGABS_BASE_NR: u8 = 0x40;
// EVIOCSREP / EVIOCSFF / EVIOCRMFF / EVIOCGRAB / EVIOCREVOKE:
pub const EVIOCSREP:    u64 = 0x40084503;
pub const EVIOCSFF:     u64 = 0x402c4580;
pub const EVIOCRMFF:    u64 = 0x40044581;
pub const EVIOCGRAB:    u64 = 0x40044590;
pub const EVIOCREVOKE:  u64 = 0x40044591;
pub const EVIOCGEFFECTS:u64 = 0x80044584;

// ============================================================
// Wire structs
// ============================================================

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VirtioInputEvent { pub ty: u16, pub code: u16, pub value: u32 }

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VirtioInputAbsInfo {
    pub min: u32, pub max: u32, pub fuzz: u32, pub flat: u32, pub res: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VirtioInputDevIds {
    pub bustype: u16, pub vendor: u16, pub product: u16, pub version: u16,
}

// Linux input_event (8 bytes type/code/value + struct timeval kernel-stamped)
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct InputEvent {
    pub tv_sec:  u64,
    pub tv_usec: u64,
    pub ty:      u16,
    pub code:    u16,
    pub value:   u32,
}

// ============================================================
// Driver state
// ============================================================

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { NoDevice, FeaturesNotOk, BringUpFail, Inval, Busy }

pub type KResult<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct CapBitmap { pub bits: [u8; 96] }
impl Default for CapBitmap { fn default() -> Self { Self { bits: [0u8; 96] } } }

pub struct VirtioInputDev {
    pub bdf:        u32,
    pub evdev_id:   u32,
    pub name:       [u8; 128],
    pub name_len:   usize,
    pub serial:     [u8; 128],
    pub serial_len: usize,
    pub ids:        VirtioInputDevIds,
    pub ev_bits:    [u8; 32],     // supported EV_* types, bit per type
    pub key_bits:   CapBitmap,    // KEY_*  range
    pub rel_bits:   CapBitmap,    // REL_*  range
    pub abs_bits:   CapBitmap,    // ABS_*  range
    pub led_bits:   CapBitmap,
    pub abs_info:   [Option<VirtioInputAbsInfo>; 64],
}

// ============================================================
// Crate entry points
// ============================================================

/// Boot-time registration with the driver-model registry.
/// # C: O(1)
pub fn register() {
    drv::register(drv::DriverEntry { name: "virtio-input", probe });
}

/// Boot-time per-device probe shim. Real bring-up (queue setup +
/// config-space scan + EVENTQ pre-fill) lands when the kernel's
/// pci_boot picks up vendor=0x1AF4 device=0x1052 and calls into
/// `install`.
/// # C: O(1)
pub fn probe(_bdf: u32) -> drv::KResult<()> { Err(drv::Error::NoMatch) }

/// Multi-device registry. v1 supports up to 8 simultaneous evdev
/// devices (kbd + mouse + tablet + spares).
static DEVICES: Spinlock<Vec<VirtioInputDev>, DriverLockClass>
    = Spinlock::new(Vec::new());

/// Surface for the kernel to install a per-device record after
/// running modern-transport bring-up + the config-space identity
/// reads from `46§5`.
/// # C: O(1)
pub fn install(dev: VirtioInputDev) {
    DEVICES.lock().push(dev);
}

/// Number of installed evdev devices.
/// # C: O(1)
pub fn count() -> usize { DEVICES.lock().len() }

/// Snapshot the friendly name for `evdev_id` if installed.
/// # C: O(N)
pub fn name_of(evdev_id: u32) -> Option<[u8; 128]> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).map(|d| d.name)
}

/// Dispatch an EVIOC* ioctl. Returns `Some(rv)` if recognised.
/// Matches by `(group=='E', cmd_nr)` so variable-length ioctls
/// (`EVIOCGNAME(len)`, `EVIOCGBIT(ev, len)`, `EVIOCGABS(axis)`)
/// dispatch the same as fixed-size ones.
/// # C: O(1)
pub fn dispatch_ioctl(evdev_id: u32, req: u64, _arg: u64) -> Option<i64> {
    let group = ((req >> 8) & 0xFF) as u8;
    if group != EVIOC_GROUP { return None; }
    let nr = (req & 0xFF) as u8;
    let _ = evdev_id;
    // Acknowledge known nr values; the kernel ioctl-glue path
    // performs the actual user-buffer writeback per `46§7`. This
    // table is the per-driver intercept point for future hotplug
    // + grab arbitration.
    match nr {
        0x01 => Some(0),                    // EVIOCGVERSION
        0x02 => Some(0),                    // EVIOCGID
        0x03 => Some(0),                    // EVIOCSREP
        EVIOCGNAME_NR | EVIOCGUNIQ_NR | EVIOCGPROP_NR
        | EVIOCGKEY_NR | EVIOCGLED_NR | EVIOCGSND_NR | EVIOCGSW_NR => Some(0),
        n if n >= EVIOCGBIT_BASE_NR
             && n < EVIOCGBIT_BASE_NR.saturating_add(0x1f) => Some(0),
        n if n >= EVIOCGABS_BASE_NR
             && n < EVIOCGABS_BASE_NR.saturating_add(0x3f) => Some(0),
        0x80 | 0x81 | 0x84 | 0x90 | 0x91 => Some(0),  // EVIOCSFF/RMFF/EFFECTS/GRAB/REVOKE
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_layout() {
        // virtio_input_event = 8 bytes (type + code + value)
        assert_eq!(core::mem::size_of::<VirtioInputEvent>(), 8);
    }

    #[test]
    fn absinfo_layout() {
        // 5 × u32 = 20 bytes
        assert_eq!(core::mem::size_of::<VirtioInputAbsInfo>(), 20);
    }

    #[test]
    fn devids_layout() {
        // 4 × u16 = 8 bytes
        assert_eq!(core::mem::size_of::<VirtioInputDevIds>(), 8);
    }

    #[test]
    fn install_count_roundtrip() {
        DEVICES.lock().clear();
        assert_eq!(count(), 0);
        install(VirtioInputDev {
            bdf:        0,
            evdev_id:   0,
            name:       [0; 128],
            name_len:   0,
            serial:     [0; 128],
            serial_len: 0,
            ids:        VirtioInputDevIds::default(),
            ev_bits:    [0; 32],
            key_bits:   CapBitmap::default(),
            rel_bits:   CapBitmap::default(),
            abs_bits:   CapBitmap::default(),
            led_bits:   CapBitmap::default(),
            abs_info:   [None; 64],
        });
        assert_eq!(count(), 1);
        DEVICES.lock().clear();
    }

    #[test]
    fn ioctl_dispatch_recognises_evdev_group() {
        // EVIOCGVERSION = 0x80044501. Group 'E' = 0x45 at byte 1.
        assert!(matches!(dispatch_ioctl(0, EVIOCGVERSION, 0), Some(_)));
        // Unknown group returns None.
        assert_eq!(dispatch_ioctl(0, 0x80044001, 0), None);
    }

    #[test]
    fn ioctl_dispatch_handles_evdev_bit_range() {
        // EVIOCGBIT(EV_KEY, 96) = _IOR('E', 0x20+EV_KEY=0x21, 96) — encoded.
        // group='E' at byte 1; nr=0x21 at byte 0; size=96 at byte 2..3.
        let req = 0x80604521u64;
        assert!(matches!(dispatch_ioctl(0, req, 0), Some(_)));
    }
}
