use vfs::{File, InodeRef};

use crate::devfs::shared::{
    file_token, release_grab, EVDEV_FILE_REVOKED, EVDEV_GRABS, EVDEV_INO_BASE,
};
use crate::evdev_queue::MAX_EVDEV;

#[inline]
fn ioc_nr(req: u64) -> u32 {
    (req & crate::IOC_NR_MASK) as u32
}

#[inline]
fn ioc_type(req: u64) -> u32 {
    ((req >> crate::IOC_TYPE_SHIFT) & crate::IOC_TYPE_MASK) as u32
}

#[inline]
fn ioc_size(req: u64) -> usize {
    ((req >> crate::IOC_SIZE_SHIFT) & crate::IOC_SIZE_MASK) as usize
}

#[inline]
fn ioc_dir(req: u64) -> u32 {
    ((req >> crate::IOC_DIR_SHIFT) & crate::IOC_DIR_MASK) as u32
}

unsafe fn uwrite(arg: u64, src: &[u8], cap: usize) -> i64 {
    let n = src.len().min(cap);
    unsafe {
        for i in 0..n {
            core::ptr::write_volatile((arg + i as u64) as *mut u8, src[i]);
        }
    }
    n as i64
}

unsafe fn uzero(arg: u64, cap: usize) -> i64 {
    unsafe {
        for i in 0..cap {
            core::ptr::write_volatile((arg + i as u64) as *mut u8, 0);
        }
    }
    cap as i64
}

fn err(errno: syscall::errno::Errno) -> i64 {
    -(errno.as_i32() as i64)
}

fn valid_user_range(arg: u64, bytes: u64) -> bool {
    arg != 0
        && arg < hal::USER_VA_END
        && arg.checked_add(bytes).is_some_and(|end| end <= hal::USER_VA_END)
}

unsafe fn uread_i32(arg: u64) -> i32 {
    let mut b = [0u8; 4];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = unsafe { core::ptr::read_volatile((arg + i as u64) as *const u8) };
    }
    i32::from_le_bytes(b)
}

unsafe fn uread_u32(arg: u64) -> u32 {
    let mut b = [0u8; 4];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = unsafe { core::ptr::read_volatile((arg + i as u64) as *const u8) };
    }
    u32::from_le_bytes(b)
}

pub fn handle_evdev_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    let inode: &InodeRef = file.inode();
    let ino = inode.ino();
    if (ino & !crate::IOC_NR_MASK) != EVDEV_INO_BASE || (ino & crate::IOC_NR_MASK) == 0 {
        return None;
    }
    use syscall::errno::Errno;
    if ioc_type(req) != b'E' as u32 {
        return None;
    }
    let nr = ioc_nr(req);

    if nr == crate::EVIOCSCLOCKID_NR as u32 {
        if !valid_user_range(arg, crate::EVDEV_CLOCKID_BYTES as u64) {
            return Some(err(Errno::Efault));
        }
        let clock_id = unsafe { uread_i32(arg) };
        return Some(if clock_id == crate::EVDEV_CLOCK_MONOTONIC { 0 } else { err(Errno::Einval) });
    }

    let evdev_id = ((ino & crate::IOC_NR_MASK) - 1) as u32;
    if nr == crate::EVIOCREP_NR as u32 {
        if !valid_user_range(arg, crate::EVDEV_REPEAT_BYTES as u64) {
            return Some(err(Errno::Efault));
        }
        match ioc_dir(req) {
            crate::IOC_READ => {
                let repeat = crate::repeat(evdev_id).unwrap_or(crate::DEFAULT_REPEAT);
                let mut b = [0u8; crate::EVDEV_REPEAT_BYTES];
                b[0..crate::EVDEV_CLOCKID_BYTES].copy_from_slice(&repeat[0].to_le_bytes());
                b[crate::EVDEV_CLOCKID_BYTES..crate::EVDEV_REPEAT_BYTES]
                    .copy_from_slice(&repeat[1].to_le_bytes());
                return Some(unsafe { uwrite(arg, &b, crate::EVDEV_REPEAT_BYTES) });
            }
            crate::IOC_WRITE => {
                let delay = unsafe { uread_u32(arg) };
                let period = unsafe { uread_u32(arg + crate::EVDEV_CLOCKID_BYTES as u64) };
                if !crate::set_repeat(evdev_id, [delay, period]) {
                    return Some(err(Errno::Enodev));
                }
                return Some(0);
            }
            _ => return Some(err(Errno::Enotty)),
        }
    }

    if nr == crate::EVIOCGRAB_NR as u32 {
        let token = file_token(file);
        let slot = (evdev_id as usize).min(MAX_EVDEV - 1);
        if arg != 0 {
            let taken = {
                let mut grabs = EVDEV_GRABS.lock();
                if grabs[slot] == 0 || grabs[slot] == token { grabs[slot] = token; true } else { false }
            };
            if !taken { return Some(err(Errno::Ebusy)); }
            // A grab makes `poll_open_file` drop POLLIN for every OTHER open
            // description (`grabbed_by_other`), so it is a readiness
            // transition and needs the same wake an incoming event gets —
            // Linux `evdev_grab` runs under the client list and the ungrabbed
            // clients simply stop being fed. Without this the change is only
            // observable on a rescan.
            super::fileops::notify_evdev_subs(evdev_id);
            return Some(0);
        }
        release_grab(evdev_id, token);
        super::fileops::notify_evdev_subs(evdev_id);
        return Some(0);
    }

    if nr == crate::EVIOCREVOKE_NR as u32 {
        if arg != 0 {
            file.set_private_data(file.private_data() | EVDEV_FILE_REVOKED);
            release_grab(evdev_id, file_token(file));
            // `evdev_revoke` marks the client revoked and wakes it
            // (`drivers/input/evdev.c`): its poll flips to EPOLLHUP and every
            // read returns ENODEV, so a parked waiter must be released.
            super::fileops::notify_evdev_subs(evdev_id);
        }
        return Some(0);
    }

    if !valid_user_range(arg, 1) {
        return Some(err(Errno::Efault));
    }
    let size = ioc_size(req);
    let dev = crate::device(evdev_id);

    let rv: i64 = unsafe {
        match nr {
            nr if nr == crate::EVIOCGVERSION_NR as u32 => {
                uwrite(arg, &crate::EVDEV_VERSION.to_le_bytes(), size.max(crate::EVDEV_CLOCKID_BYTES));
                0
            }
            nr if nr == crate::EVIOCGID_NR as u32 => {
                let ids = dev.as_ref().map(|d| d.ids).unwrap_or_default();
                let mut b = [0u8; crate::EVDEV_ID_BYTES];
                b[crate::EVDEV_ID_BUSTYPE_OFF..crate::EVDEV_ID_VENDOR_OFF]
                    .copy_from_slice(&ids.bustype.to_le_bytes());
                b[crate::EVDEV_ID_VENDOR_OFF..crate::EVDEV_ID_PRODUCT_OFF]
                    .copy_from_slice(&ids.vendor.to_le_bytes());
                b[crate::EVDEV_ID_PRODUCT_OFF..crate::EVDEV_ID_VERSION_OFF]
                    .copy_from_slice(&ids.product.to_le_bytes());
                b[crate::EVDEV_ID_VERSION_OFF..crate::EVDEV_ID_BYTES]
                    .copy_from_slice(&ids.version.to_le_bytes());
                uwrite(arg, &b, size.max(crate::EVDEV_ID_BYTES));
                0
            }
            nr if nr == crate::EVIOCGNAME_NR as u32 => match dev.as_ref() {
                Some(d) => {
                    let len = d.name_len.min(d.name.len());
                    let mut b = [0u8; crate::EVDEV_STR_BYTES];
                    b[..len].copy_from_slice(&d.name[..len]);
                    uwrite(arg, &b[..len + 1], size)
                }
                None => uzero(arg, size),
            },
            nr if nr == crate::EVIOCGPHYS_NR as u32 => uzero(arg, size),
            nr if nr == crate::EVIOCGUNIQ_NR as u32 => match dev.as_ref() {
                Some(d) if d.serial_len > 0 => {
                    let len = d.serial_len.min(d.serial.len());
                    let mut b = [0u8; crate::EVDEV_STR_BYTES];
                    b[..len].copy_from_slice(&d.serial[..len]);
                    uwrite(arg, &b[..len + 1], size)
                }
                _ => uzero(arg, size),
            },
            nr if nr == crate::EVIOCGPROP_NR as u32 => match dev.as_ref() {
                Some(d) => uwrite(arg, &d.prop_bits, size),
                None => uzero(arg, size),
            },
            nr if matches!(nr,
                x if x == crate::EVIOCGKEY_NR as u32
                    || x == crate::EVIOCGLED_NR as u32
                    || x == crate::EVIOCGSND_NR as u32
                    || x == crate::EVIOCGSW_NR as u32
            ) => uzero(arg, size),
            nr if (crate::EVIOCGBIT_BASE_NR as u32..crate::EVIOCGABS_BASE_NR as u32).contains(&nr) => {
                let ev = nr - crate::EVIOCGBIT_BASE_NR as u32;
                match (dev.as_ref(), ev) {
                    (Some(d), ev) if ev == crate::EV_SYN as u32 => uwrite(arg, &d.ev_bits, size),
                    (Some(d), ev) if ev == crate::EV_KEY as u32 => uwrite(arg, &d.key_bits.bits, size),
                    (Some(d), ev) if ev == crate::EV_REL as u32 => uwrite(arg, &d.rel_bits.bits, size),
                    (Some(d), ev) if ev == crate::EV_ABS as u32 => uwrite(arg, &d.abs_bits.bits, size),
                    (Some(d), ev) if ev == crate::EV_LED as u32 => uwrite(arg, &d.led_bits.bits, size),
                    _ => uzero(arg, size),
                }
            }
            nr if (crate::EVIOCGABS_BASE_NR as u32..crate::EVIOCGABS_END_NR as u32).contains(&nr) => {
                let axis = (nr - crate::EVIOCGABS_BASE_NR as u32) as usize;
                let ai = dev.as_ref().and_then(|d| d.abs_info.get(axis).copied().flatten());
                let mut b = [0u8; crate::EVDEV_ABSINFO_BYTES];
                if let Some(a) = ai {
                    b[crate::EVDEV_ABSINFO_MIN_OFF..crate::EVDEV_ABSINFO_MAX_OFF]
                        .copy_from_slice(&a.min.to_le_bytes());
                    b[crate::EVDEV_ABSINFO_MAX_OFF..crate::EVDEV_ABSINFO_FUZZ_OFF]
                        .copy_from_slice(&a.max.to_le_bytes());
                    b[crate::EVDEV_ABSINFO_FUZZ_OFF..crate::EVDEV_ABSINFO_FLAT_OFF]
                        .copy_from_slice(&a.fuzz.to_le_bytes());
                    b[crate::EVDEV_ABSINFO_FLAT_OFF..crate::EVDEV_ABSINFO_RES_OFF]
                        .copy_from_slice(&a.flat.to_le_bytes());
                    b[crate::EVDEV_ABSINFO_RES_OFF..crate::EVDEV_ABSINFO_BYTES]
                        .copy_from_slice(&a.res.to_le_bytes());
                }
                uwrite(arg, &b, size.max(crate::EVDEV_ABSINFO_BYTES))
            }
            _ => return Some(err(Errno::Enotty)),
        }
    };
    Some(rv)
}
