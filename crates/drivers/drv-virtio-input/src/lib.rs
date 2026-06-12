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

#[derive(Clone)]
pub struct VirtioInputDev {
    pub bdf:        u32,
    pub evdev_id:   u32,
    /// Device class: a pointer (mouse/tablet — advertises EV_REL/EV_ABS) vs
    /// a keyboard. Only keyboard-class devices feed the console keyboard
    /// pipeline (mirrors Linux binding the VT keyboard input_handler to
    /// keyboard-capability devices, not pointers).
    pub is_pointer: bool,
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
    pub prop_bits:  [u8; 4],      // INPUT_PROP_* device properties
}

// ============================================================
// Crate entry points
// ============================================================

// virtio-input binds via the real driver-model Driver registered + bound at
// its bring-up site (pci_boot/virtio_drv.rs → drv::bind), not a probe stub. The
// old NoMatch DriverEntry (legacy drv::probe_all path, never called) was
// removed in drivers-plan D2.

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

/// Select `(select, subsel)` on the device config and return the reported
/// `size` (valid bytes in the config union @8). The virtio_input_config
/// header is `{u8 select@0; u8 subsel@1; u8 size@2; ...}` (docs/46§4).
/// # SAFETY: `cfg_va` is the Device-attr-mapped device-cfg window owned by
/// the caller; the select/subsel stores drive the device's config recompute.
unsafe fn cfg_select(cfg_va: u64, select: u8, subsel: u8) -> u8 {
    // SAFETY: per fn contract; aligned u8 MMIO ops on the config header.
    unsafe {
        core::ptr::write_volatile(cfg_va as *mut u8, select);
        core::ptr::write_volatile((cfg_va + 1) as *mut u8, subsel);
        core::ptr::read_volatile((cfg_va + 2) as *const u8)
    }
}

/// Copy the selected config union (bytes @8, length = current `size`) into
/// `dst`, returning the byte count copied (≤ dst.len, ≤ 128).
/// # SAFETY: `cfg_va` is the Device-attr-mapped device-cfg window; a config
/// item was just selected via `cfg_select`.
unsafe fn cfg_payload(cfg_va: u64, dst: &mut [u8]) -> usize {
    // SAFETY: per fn contract; aligned u8 reads of `size` payload bytes @8.
    let size = unsafe { core::ptr::read_volatile((cfg_va + 2) as *const u8) } as usize;
    let n = size.min(dst.len()).min(128);
    for i in 0..n {
        // SAFETY: i < size ≤ 128; reads stay within the config union window.
        dst[i] = unsafe { core::ptr::read_volatile((cfg_va + 8 + i as u64) as *const u8) };
    }
    n
}

/// Probe one virtio-input device: read its identity + full capability
/// bitmaps from config space (the Linux virtio_input.c probe sequence,
/// docs/46§5) and register it. Returns the assigned evdev id.
/// # SAFETY: `cfg_va` is the Device-attr-mapped virtio-input device-cfg
/// window owned by the caller for the device's lifetime.
/// # C: O(abs axes) config round-trips
pub unsafe fn install_device(bdf: u32, cfg_va: u64) -> u32 {
    let evdev_id = count() as u32;
    let mut dev = VirtioInputDev {
        bdf, evdev_id, is_pointer: false,
        name: [0; 128], name_len: 0, serial: [0; 128], serial_len: 0,
        ids: VirtioInputDevIds::default(),
        ev_bits: [0; 32],
        key_bits: CapBitmap::default(),
        rel_bits: CapBitmap::default(),
        abs_bits: CapBitmap::default(),
        led_bits: CapBitmap::default(),
        abs_info: [None; 64],
        prop_bits: [0; 4],
    };
    // SAFETY: cfg_va valid per fn contract; the config protocol is a series
    // of select/subsel writes + size/payload reads with no other effect.
    unsafe {
        // ID_NAME → friendly name.
        let _ = cfg_select(cfg_va, VIRTIO_INPUT_CFG_ID_NAME, 0);
        dev.name_len = cfg_payload(cfg_va, &mut dev.name);
        // ID_SERIAL → unique string.
        let _ = cfg_select(cfg_va, VIRTIO_INPUT_CFG_ID_SERIAL, 0);
        dev.serial_len = cfg_payload(cfg_va, &mut dev.serial);
        // ID_DEVIDS → bustype/vendor/product/version (4 × le16).
        let n = cfg_select(cfg_va, VIRTIO_INPUT_CFG_ID_DEVIDS, 0);
        if n >= 8 {
            let rd16 = |o: u64| (core::ptr::read_volatile((cfg_va + 8 + o) as *const u8) as u16)
                | ((core::ptr::read_volatile((cfg_va + 9 + o) as *const u8) as u16) << 8);
            dev.ids = VirtioInputDevIds {
                bustype: rd16(0), vendor: rd16(2), product: rd16(4), version: rd16(6),
            };
        }
        // PROP_BITS → device properties.
        let _ = cfg_select(cfg_va, VIRTIO_INPUT_CFG_PROP_BITS, 0);
        let _ = cfg_payload(cfg_va, &mut dev.prop_bits);
        // EV_BITS: virtio reports per-type. `subsel = EV_<type>` returns the
        // supported-code bitmap for that type, and a non-zero `size` means the
        // type itself is supported — so the EV-type bitmap is BUILT by probing
        // each type and setting bit `subsel` when size>0 (Linux
        // virtio_input.c::virtinput_cfg_bits + set_bit(subsel, evbit)). There is
        // no subsel=0 "supported types" read; subsel=0 is EV_SYN's codes.
        let mut abs_sz = 0u8;
        for ty in 0u8..32 {
            let sz = cfg_select(cfg_va, VIRTIO_INPUT_CFG_EV_BITS, ty);
            if sz == 0 { continue; }
            dev.ev_bits[(ty / 8) as usize] |= 1 << (ty % 8);
            match ty as u16 {
                EV_KEY => { let _ = cfg_payload(cfg_va, &mut dev.key_bits.bits); }
                EV_REL => { let _ = cfg_payload(cfg_va, &mut dev.rel_bits.bits); }
                EV_ABS => { abs_sz = sz; let _ = cfg_payload(cfg_va, &mut dev.abs_bits.bits); }
                EV_LED => { let _ = cfg_payload(cfg_va, &mut dev.led_bits.bits); }
                _ => {}
            }
        }
        // ABS_INFO for each supported ABS axis.
        if abs_sz > 0 {
            for axis in 0..64u8 {
                if dev.abs_bits.bits[(axis / 8) as usize] & (1 << (axis % 8)) == 0 { continue; }
                let m = cfg_select(cfg_va, VIRTIO_INPUT_CFG_ABS_INFO, axis);
                if m >= 20 {
                    let rd32 = |o: u64| {
                        let mut v = 0u32;
                        for b in 0..4 { v |= (core::ptr::read_volatile((cfg_va + 8 + o + b) as *const u8) as u32) << (b * 8); }
                        v
                    };
                    dev.abs_info[axis as usize] = Some(VirtioInputAbsInfo {
                        min: rd32(0), max: rd32(4), fuzz: rd32(8), flat: rd32(12), res: rd32(16),
                    });
                }
            }
        }
        // Class: a pointer advertises EV_REL or EV_ABS.
        dev.is_pointer = (dev.ev_bits[(EV_REL / 8) as usize] & (1 << (EV_REL % 8))) != 0
            || (dev.ev_bits[(EV_ABS / 8) as usize] & (1 << (EV_ABS % 8))) != 0;
    }
    install(dev);
    evdev_id
}

/// Snapshot the friendly name for `evdev_id` if installed.
/// # C: O(N)
pub fn name_of(evdev_id: u32) -> Option<[u8; 128]> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).map(|d| d.name)
}

/// Clone the full device record for `evdev_id` (identity + capability
/// bitmaps + absinfo). The EVIOCG* ioctls copy from this snapshot so the
/// DEVICES lock isn't held across the user-buffer writes. # C: O(N)
pub fn device(evdev_id: u32) -> Option<VirtioInputDev> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).cloned()
}

/// True iff `evdev_id` is a pointer (mouse/tablet). Drives the drain's
/// console-keyboard gating: pointer devices don't feed the console.
/// Unknown ids default to keyboard-class (false). # C: O(N)
pub fn is_pointer(evdev_id: u32) -> bool {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).map_or(false, |d| d.is_pointer)
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
            is_pointer: false,
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
            prop_bits:  [0; 4],
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


#[cfg(target_os = "oxide-kernel")]
pub mod devfs;

#[cfg(target_os = "oxide-kernel")]
pub mod drain;

#[cfg(target_os = "oxide-kernel")]
pub mod evdev_queue;

pub mod keymap;
