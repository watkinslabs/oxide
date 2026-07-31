use vfs::{File, InodeRef};

use crate::devfs::shared::{evdev_open, EvdevIdentity};

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

const fn bitmap_bytes(bits: usize) -> usize {
    bits.div_ceil(u8::BITS as usize)
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

fn exact_device(identity: EvdevIdentity) -> Option<input::VirtioInputDev> {
    input::device(identity.evdev_id).filter(|dev| {
        dev.device_key == identity.device_key
            && dev.input_id == identity.input_id
            && dev.evdev_id == identity.evdev_id
    })
}

/// Is this open file an evdev client? Linux answers with the file's own
/// `evdev_fops`; the inode NUMBER cannot, because the pseudo-inode ranges other
/// subsystems mint from overlap this one, and a foreign inode reaching the body
/// below would have its unrelated `private_data` word read back as an
/// `EvdevOpen`. The inode's own `EvdevData` is installed by exactly one place.
/// # C: O(1)
pub(crate) fn is_evdev_inode(inode: &InodeRef) -> bool {
    crate::devfs::shared::evdev_endpoint(inode).is_some()
}

pub fn handle_evdev_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    let inode: &InodeRef = file.inode();
    if !is_evdev_inode(inode) {
        return None;
    }
    use syscall::errno::Errno;
    // Every 'E' command belongs to this device from here on. Linux
    // `evdev_do_ioctl` ends in `return -EINVAL`, so an evdev file answers its
    // own command space itself and never hands an unrecognised one back to a
    // later stage — which would report ENOTTY, an errno evdev never produces.
    if ioc_type(req) != b'E' as u32 {
        return None;
    }
    let Some(opened) = evdev_open(file) else {
        return Some(err(Errno::Enodev));
    };
    if !opened.is_live() {
        return Some(err(Errno::Enodev));
    }
    let identity = opened.identity();
    let nr = ioc_nr(req);

    if nr == crate::EVIOCSCLOCKID_NR as u32 {
        if !valid_user_range(arg, crate::EVDEV_CLOCKID_BYTES as u64) {
            return Some(err(Errno::Efault));
        }
        let clock_id = unsafe { uread_i32(arg) };
        return Some(if opened.set_clock(clock_id) { 0 } else { err(Errno::Einval) });
    }

    if nr == crate::EVIOCREP_NR as u32 {
        if !valid_user_range(arg, crate::EVDEV_REPEAT_BYTES as u64) {
            return Some(err(Errno::Efault));
        }
        match ioc_dir(req) {
            crate::IOC_READ => {
                let Some(repeat) = input::repeat_by_identity(
                    identity.device_key,
                    identity.input_id,
                    identity.evdev_id,
                ) else {
                    return Some(err(Errno::Enodev));
                };
                let mut b = [0u8; crate::EVDEV_REPEAT_BYTES];
                b[0..crate::EVDEV_CLOCKID_BYTES].copy_from_slice(&repeat[0].to_le_bytes());
                b[crate::EVDEV_CLOCKID_BYTES..crate::EVDEV_REPEAT_BYTES]
                    .copy_from_slice(&repeat[1].to_le_bytes());
                return Some(unsafe { uwrite(arg, &b, crate::EVDEV_REPEAT_BYTES) });
            }
            crate::IOC_WRITE => {
                let delay = unsafe { uread_u32(arg) };
                let period = unsafe { uread_u32(arg + crate::EVDEV_CLOCKID_BYTES as u64) };
                if !input::set_repeat_by_identity(
                    identity.device_key,
                    identity.input_id,
                    identity.evdev_id,
                    [delay, period],
                ) {
                    return Some(err(Errno::Enodev));
                }
                return Some(0);
            }
            // Neither EVIOCGREP nor EVIOCSREP: not a command evdev names, so
            // it lands on the trailing EINVAL like any other unknown.
            _ => return Some(err(Errno::Einval)),
        }
    }

    if nr == crate::EVIOCGRAB_NR as u32 {
        if arg != 0 {
            return Some(if opened.try_grab() { 0 } else { err(Errno::Ebusy) });
        }
        return Some(if opened.ungrab() { 0 } else { err(Errno::Einval) });
    }

    if nr == crate::EVIOCREVOKE_NR as u32 {
        if arg != 0 {
            return Some(err(Errno::Einval));
        }
        opened.revoke();
        return Some(0);
    }

    // Force feedback. Effect upload and erase are refused by the input core
    // before they reach a driver whenever the device has no force-feedback
    // engine, and the errno for that is ENOSYS — no virtio-input device carries
    // one. The effect-slot count is the same question asked non-destructively,
    // and its answer for such a device is zero, not an error.
    if nr == crate::EVIOCSFF_NR as u32 || nr == crate::EVIOCRMFF_NR as u32 {
        return Some(err(Errno::Enosys));
    }
    if nr == crate::EVIOCGEFFECTS_NR as u32 {
        if !valid_user_range(arg, crate::EVDEV_CLOCKID_BYTES as u64) {
            return Some(err(Errno::Efault));
        }
        // SAFETY: arg validated inside user VA for the one int this command writes.
        unsafe { uwrite(arg, &0i32.to_le_bytes(), crate::EVDEV_CLOCKID_BYTES); }
        return Some(0);
    }

    let size = ioc_size(req);
    let required = match nr {
        nr if nr == crate::EVIOCGVERSION_NR as u32 => crate::EVDEV_CLOCKID_BYTES,
        nr if nr == crate::EVIOCGID_NR as u32 => crate::EVDEV_ID_BYTES,
        nr if (crate::EVIOCGABS_BASE_NR as u32..crate::EVIOCGABS_END_NR as u32).contains(&nr) => {
            crate::EVDEV_ABSINFO_BYTES
        }
        _ => size.max(1),
    };
    if !valid_user_range(arg, required as u64) {
        return Some(err(Errno::Efault));
    }
    let dev = exact_device(identity);

    let rv: i64 = unsafe {
        match nr {
            nr if nr == crate::EVIOCGVERSION_NR as u32 => {
                uwrite(arg, &crate::EVDEV_VERSION.to_le_bytes(), size.max(crate::EVDEV_CLOCKID_BYTES));
                0
            }
            nr if nr == crate::EVIOCGID_NR as u32 => {
                let Some(dev) = dev.as_ref() else {
                    return Some(err(Errno::Enodev));
                };
                let ids = dev.ids;
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
                Some(d) if d.name_present => {
                    let len = d.name_len.min(d.name.len());
                    let mut b = [0u8; crate::EVDEV_STR_BYTES];
                    b[..len].copy_from_slice(&d.name[..len]);
                    uwrite(arg, &b[..len + 1], size)
                }
                Some(_) => err(Errno::Enoent),
                None => err(Errno::Enodev),
            },
            nr if nr == crate::EVIOCGPHYS_NR as u32 => match dev.as_ref() {
                Some(d) if d.phys_present => {
                    let len = d.phys_len.min(d.phys.len());
                    let mut b = [0u8; crate::EVDEV_STR_BYTES];
                    b[..len].copy_from_slice(&d.phys[..len]);
                    uwrite(arg, &b[..len + 1], size)
                }
                Some(_) => err(Errno::Enoent),
                None => err(Errno::Enodev),
            },
            nr if nr == crate::EVIOCGUNIQ_NR as u32 => match dev.as_ref() {
                Some(d) if d.serial_present => {
                    let len = d.serial_len.min(d.serial.len());
                    let mut b = [0u8; crate::EVDEV_STR_BYTES];
                    b[..len].copy_from_slice(&d.serial[..len]);
                    uwrite(arg, &b[..len + 1], size)
                }
                Some(_) => err(Errno::Enoent),
                None => err(Errno::Enodev),
            },
            nr if nr == crate::EVIOCGPROP_NR as u32 => match dev.as_ref() {
                Some(d) => uwrite(
                    arg,
                    &d.prop_bits[..bitmap_bytes(input::INPUT_PROP_CNT)],
                    size,
                ),
                None => err(Errno::Enodev),
            },
            nr if matches!(nr,
                x if x == crate::EVIOCGKEY_NR as u32
                    || x == crate::EVIOCGLED_NR as u32
                    || x == crate::EVIOCGSND_NR as u32
                    || x == crate::EVIOCGSW_NR as u32
            ) => {
                let ev_type = match nr {
                    x if x == crate::EVIOCGKEY_NR as u32 => crate::EV_KEY,
                    x if x == crate::EVIOCGLED_NR as u32 => crate::EV_LED,
                    x if x == crate::EVIOCGSND_NR as u32 => crate::EV_SND,
                    _ => crate::EV_SW,
                };
                let mut state = [0u8; crate::EVDEV_STATE_BYTES];
                match input::with_state_bits_by_identity(
                    identity.device_key,
                    identity.input_id,
                    identity.evdev_id,
                    ev_type,
                    |bits| opened.copy_state_and_flush(
                        ev_type,
                        bits,
                        &mut state[..size.min(crate::EVDEV_STATE_BYTES)],
                    ),
                ) {
                    Some(len) => uwrite(arg, &state[..len], len),
                    None => err(Errno::Enodev),
                }
            }
            nr if (crate::EVIOCGBIT_BASE_NR as u32..crate::EVIOCGABS_BASE_NR as u32).contains(&nr) => {
                let ev_type = (nr - crate::EVIOCGBIT_BASE_NR as u32) as u16;
                match dev.as_ref() {
                    Some(dev) => match dev.capability_bits(ev_type) {
                        Some(bits) => uwrite(arg, bits, size),
                        None => err(Errno::Einval),
                    },
                    None => err(Errno::Enodev),
                }
            }
            nr if (crate::EVIOCGABS_BASE_NR as u32..crate::EVIOCGABS_END_NR as u32).contains(&nr) => {
                let axis = (nr - crate::EVIOCGABS_BASE_NR as u32) as u16;
                let Some(snapshot) = input::abs_snapshot_by_identity(
                    identity.device_key,
                    identity.input_id,
                    identity.evdev_id,
                    axis,
                ) else {
                    return Some(if exact_device(identity).is_some() {
                        err(Errno::Einval)
                    } else {
                        err(Errno::Enodev)
                    });
                };
                let mut b = [0u8; crate::EVDEV_ABSINFO_BYTES];
                b[crate::EVDEV_ABSINFO_VALUE_OFF..crate::EVDEV_ABSINFO_MIN_OFF]
                    .copy_from_slice(&snapshot.value.to_le_bytes());
                b[crate::EVDEV_ABSINFO_MIN_OFF..crate::EVDEV_ABSINFO_MAX_OFF]
                    .copy_from_slice(&snapshot.parameters.min.to_le_bytes());
                b[crate::EVDEV_ABSINFO_MAX_OFF..crate::EVDEV_ABSINFO_FUZZ_OFF]
                    .copy_from_slice(&snapshot.parameters.max.to_le_bytes());
                b[crate::EVDEV_ABSINFO_FUZZ_OFF..crate::EVDEV_ABSINFO_FLAT_OFF]
                    .copy_from_slice(&snapshot.parameters.fuzz.to_le_bytes());
                b[crate::EVDEV_ABSINFO_FLAT_OFF..crate::EVDEV_ABSINFO_RES_OFF]
                    .copy_from_slice(&snapshot.parameters.flat.to_le_bytes());
                b[crate::EVDEV_ABSINFO_RES_OFF..crate::EVDEV_ABSINFO_BYTES]
                    .copy_from_slice(&snapshot.parameters.res.to_le_bytes());
                uwrite(arg, &b, size.max(crate::EVDEV_ABSINFO_BYTES))
            }
            // Linux `evdev_do_ioctl` falls off its multi-number handlers into
            // `return -EINVAL`; ENOTTY is not in evdev's vocabulary.
            _ => return Some(err(Errno::Einval)),
        }
    };
    Some(rv)
}
