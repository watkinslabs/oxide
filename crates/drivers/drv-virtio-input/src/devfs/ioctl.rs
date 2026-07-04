use vfs::{File, InodeRef};

use crate::devfs::shared::{
    file_token, release_grab, EVDEV_FILE_REVOKED, EVDEV_GRABS, EVDEV_INO_BASE,
};
use crate::evdev_queue::MAX_EVDEV;

#[inline]
fn ioc_nr(req: u64) -> u32 {
    (req & 0xFF) as u32
}

#[inline]
fn ioc_type(req: u64) -> u32 {
    ((req >> 8) & 0xFF) as u32
}

#[inline]
fn ioc_size(req: u64) -> usize {
    ((req >> 16) & 0x3FFF) as usize
}

#[inline]
fn ioc_dir(req: u64) -> u32 {
    ((req >> 30) & 0x3) as u32
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
    if (ino & !0xFF) != EVDEV_INO_BASE || (ino & 0xFF) == 0 {
        return None;
    }
    use syscall::errno::Errno;
    if ioc_type(req) != b'E' as u32 {
        return None;
    }
    let nr = ioc_nr(req);

    const EVIOCGRAB_NR: u32 = 0x90;
    const EVIOCREVOKE_NR: u32 = 0x91;
    const EVIOCSCLOCKID_NR: u32 = 0xa0;
    const CLOCK_MONOTONIC: i32 = 1;
    const IOC_WRITE: u32 = 1;
    const IOC_READ: u32 = 2;

    if nr == EVIOCSCLOCKID_NR {
        if !valid_user_range(arg, 4) {
            return Some(err(Errno::Efault));
        }
        let clock_id = unsafe { uread_i32(arg) };
        return Some(if clock_id == CLOCK_MONOTONIC { 0 } else { err(Errno::Einval) });
    }

    let evdev_id = ((ino & 0xFF) - 1) as u32;
    if nr == crate::EVIOCREP_NR as u32 {
        if !valid_user_range(arg, 8) {
            return Some(err(Errno::Efault));
        }
        match ioc_dir(req) {
            IOC_READ => {
                let repeat = crate::repeat(evdev_id).unwrap_or(crate::DEFAULT_REPEAT);
                let mut b = [0u8; 8];
                b[0..4].copy_from_slice(&repeat[0].to_le_bytes());
                b[4..8].copy_from_slice(&repeat[1].to_le_bytes());
                return Some(unsafe { uwrite(arg, &b, 8) });
            }
            IOC_WRITE => {
                let delay = unsafe { uread_u32(arg) };
                let period = unsafe { uread_u32(arg + 4) };
                if !crate::set_repeat(evdev_id, [delay, period]) {
                    return Some(err(Errno::Enodev));
                }
                return Some(0);
            }
            _ => return Some(err(Errno::Enotty)),
        }
    }

    if nr == EVIOCGRAB_NR {
        let token = file_token(file);
        let slot = (evdev_id as usize).min(MAX_EVDEV - 1);
        if arg != 0 {
            let mut grabs = EVDEV_GRABS.lock();
            return Some(if grabs[slot] == 0 || grabs[slot] == token {
                grabs[slot] = token;
                0
            } else {
                err(Errno::Ebusy)
            });
        }
        release_grab(evdev_id, token);
        return Some(0);
    }

    if nr == EVIOCREVOKE_NR {
        if arg != 0 {
            file.set_private_data(file.private_data() | EVDEV_FILE_REVOKED);
            release_grab(evdev_id, file_token(file));
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
            0x01 => {
                let v: u32 = 0x01_0001;
                uwrite(arg, &v.to_le_bytes(), size.max(4));
                0
            }
            0x02 => {
                let ids = dev.as_ref().map(|d| d.ids).unwrap_or_default();
                let mut b = [0u8; 8];
                b[0..2].copy_from_slice(&ids.bustype.to_le_bytes());
                b[2..4].copy_from_slice(&ids.vendor.to_le_bytes());
                b[4..6].copy_from_slice(&ids.product.to_le_bytes());
                b[6..8].copy_from_slice(&ids.version.to_le_bytes());
                uwrite(arg, &b, size.max(8));
                0
            }
            0x06 => match dev.as_ref() {
                Some(d) => {
                    let len = d.name_len.min(d.name.len());
                    let mut b = [0u8; 129];
                    b[..len].copy_from_slice(&d.name[..len]);
                    uwrite(arg, &b[..len + 1], size)
                }
                None => uzero(arg, size),
            },
            0x07 => uzero(arg, size),
            0x08 => match dev.as_ref() {
                Some(d) if d.serial_len > 0 => {
                    let len = d.serial_len.min(d.serial.len());
                    let mut b = [0u8; 129];
                    b[..len].copy_from_slice(&d.serial[..len]);
                    uwrite(arg, &b[..len + 1], size)
                }
                _ => uzero(arg, size),
            },
            0x09 => match dev.as_ref() {
                Some(d) => uwrite(arg, &d.prop_bits, size),
                None => uzero(arg, size),
            },
            0x18 | 0x19 | 0x1a | 0x1b => uzero(arg, size),
            0x20..=0x3f => {
                let ev = nr - 0x20;
                match (dev.as_ref(), ev) {
                    (Some(d), 0x00) => uwrite(arg, &d.ev_bits, size),
                    (Some(d), 0x01) => uwrite(arg, &d.key_bits.bits, size),
                    (Some(d), 0x02) => uwrite(arg, &d.rel_bits.bits, size),
                    (Some(d), 0x03) => uwrite(arg, &d.abs_bits.bits, size),
                    (Some(d), 0x11) => uwrite(arg, &d.led_bits.bits, size),
                    _ => uzero(arg, size),
                }
            }
            0x40..=0x7f => {
                let axis = (nr - 0x40) as usize;
                let ai = dev.as_ref().and_then(|d| d.abs_info.get(axis).copied().flatten());
                let mut b = [0u8; 24];
                if let Some(a) = ai {
                    b[4..8].copy_from_slice(&a.min.to_le_bytes());
                    b[8..12].copy_from_slice(&a.max.to_le_bytes());
                    b[12..16].copy_from_slice(&a.fuzz.to_le_bytes());
                    b[16..20].copy_from_slice(&a.flat.to_le_bytes());
                    b[20..24].copy_from_slice(&a.res.to_le_bytes());
                }
                uwrite(arg, &b, size.max(24))
            }
            _ => return Some(err(Errno::Enotty)),
        }
    };
    Some(rv)
}
