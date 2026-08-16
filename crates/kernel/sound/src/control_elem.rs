// SNDRV_CTL_IOCTL_ELEM_* / TLV_* against the driver-registered control
// elements. Value marshalling follows ALSA's unions: BOOLEAN and INTEGER
// carry `long` per channel from `snd_ctl_elem_value.value` and ENUMERATED
// carries `unsigned int` per channel from the same offset.

use syscall::errno::Errno;

use crate::elem::{self, ElemDesc, ElemId, ElemValues, ENUM_NAME_WIDTH, MAX_ELEM_CHANNELS};
use crate::uapi::*;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read a `snd_ctl_elem_id` starting at `off`. # C: O(name)
fn read_id(b: &UserBuf, off: usize) -> (u32, ElemId) {
    let mut name = [0u8; CEI_NAME_LEN];
    for (i, byte) in name.iter_mut().enumerate() { *byte = b.r8(off + CEI_NAME + i); }
    (b.r32(off + CEI_NUMID), ElemId {
        iface: b.r32(off + CEI_IFACE),
        device: b.r32(off + CEI_DEVICE),
        subdevice: b.r32(off + CEI_SUBDEVICE),
        name,
        index: b.r32(off + CEI_INDEX),
    })
}

/// Write a resolved `snd_ctl_elem_id` at `off`. # C: O(name)
fn write_id(b: &UserBuf, off: usize, numid: u32, id: &ElemId) {
    b.w32(off + CEI_NUMID, numid);
    b.w32(off + CEI_IFACE, id.iface);
    b.w32(off + CEI_DEVICE, id.device);
    b.w32(off + CEI_SUBDEVICE, id.subdevice);
    b.wstr(off + CEI_NAME, &id.name, CEI_NAME_LEN);
    b.w32(off + CEI_INDEX, id.index);
}

/// SNDRV_CTL_IOCTL_ELEM_LIST. # C: O(space)
pub(crate) fn list(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_LIST_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let total = elem::count(owner);
    let offset = b.r32(CEL_OFFSET);
    let space = b.r32(CEL_SPACE);
    b.w32(CEL_COUNT, total);
    let pids = b.r64(CEL_PIDS);
    if space == 0 || pids == 0 {
        b.w32(CEL_USED, 0);
        return 0;
    }
    let available = total.saturating_sub(offset);
    let used = available.min(space);
    if used == 0 {
        b.w32(CEL_USED, 0);
        return 0;
    }
    let ids = match UserBuf::new(pids, used as usize * CTL_ELEM_ID_SIZE) {
        Some(ids) => ids,
        None => return err(Errno::Efault),
    };
    for slot in 0..used {
        let written = elem::with_nth(owner, offset + slot, |numid, desc| {
            write_id(&ids, slot as usize * CTL_ELEM_ID_SIZE, numid, &desc.id);
        });
        if written.is_none() {
            b.w32(CEL_USED, slot);
            return 0;
        }
    }
    b.w32(CEL_USED, used);
    0
}

/// SNDRV_CTL_IOCTL_ELEM_INFO. # C: O(elements)
pub(crate) fn info(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let (numid, id) = read_id(&b, 0);
    let requested_item = b.r32(CEINFO_ENUM_ITEM);
    let found = elem::with_id(owner, numid, &id, |numid, desc| {
        b.zero(0, CTL_ELEM_INFO_SIZE);
        write_id(&b, 0, numid, &desc.id);
        b.w32(CEINFO_TYPE, desc.etype);
        b.w32(CEINFO_ACCESS, desc.access);
        b.w32(CEINFO_COUNT, desc.count);
        b.w32(CEINFO_OWNER, 0);
        if desc.etype == CTL_ELEM_TYPE_ENUMERATED {
            b.w32(CEINFO_ENUM_ITEMS, desc.items);
            if requested_item >= desc.items { return err(Errno::Einval); }
            b.w32(CEINFO_ENUM_ITEM, requested_item);
            let mut name = [0u8; ENUM_NAME_WIDTH];
            if !(desc.ops.enum_name)(owner, desc.private, requested_item, &mut name) {
                return err(Errno::Einval);
            }
            b.wstr(CEINFO_ENUM_NAME, &name, ENUM_NAME_WIDTH);
        } else {
            b.w64(CEINFO_INTEGER_MIN, desc.min as u64);
            b.w64(CEINFO_INTEGER_MAX, desc.max as u64);
            b.w64(CEINFO_INTEGER_STEP, desc.step as u64);
        }
        0
    });
    found.unwrap_or_else(|| err(Errno::Enoent))
}

fn load_values(b: &UserBuf, desc: &ElemDesc) -> ElemValues {
    let mut values = [0i64; MAX_ELEM_CHANNELS];
    let count = (desc.count as usize).min(MAX_ELEM_CHANNELS);
    for (channel, value) in values.iter_mut().enumerate().take(count) {
        *value = if desc.etype == CTL_ELEM_TYPE_ENUMERATED {
            b.r32(CEV_VALUE + channel * 4) as i64
        } else {
            b.r64(CEV_VALUE + channel * 8) as i64
        };
    }
    values
}

fn store_values(b: &UserBuf, desc: &ElemDesc, values: &ElemValues) {
    let count = (desc.count as usize).min(MAX_ELEM_CHANNELS);
    for (channel, value) in values.iter().enumerate().take(count) {
        if desc.etype == CTL_ELEM_TYPE_ENUMERATED {
            b.w32(CEV_VALUE + channel * 4, *value as u32);
        } else {
            b.w64(CEV_VALUE + channel * 8, *value as u64);
        }
    }
}

/// SNDRV_CTL_IOCTL_ELEM_READ. # C: O(elements + count)
pub(crate) fn read(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_VALUE_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let (numid, id) = read_id(&b, 0);
    let found = elem::with_id(owner, numid, &id, |numid, desc| {
        if desc.access & CTL_ELEM_ACCESS_READ == 0 { return err(Errno::Eperm); }
        let mut values = [0i64; MAX_ELEM_CHANNELS];
        if !(desc.ops.get)(owner, desc.private, &mut values) { return err(Errno::Eio); }
        elem::clamp_values(desc, &mut values);
        write_id(&b, 0, numid, &desc.id);
        store_values(&b, desc, &values);
        0
    });
    found.unwrap_or_else(|| err(Errno::Enoent))
}

/// SNDRV_CTL_IOCTL_ELEM_WRITE. Returns 1 when the value changed, matching
/// ALSA's changed/unchanged report. # C: O(elements + count)
pub(crate) fn write(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_VALUE_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let (numid, id) = read_id(&b, 0);
    let found = elem::with_id(owner, numid, &id, |numid, desc| {
        if desc.access & CTL_ELEM_ACCESS_WRITE == 0 { return err(Errno::Eperm); }
        let requested = load_values(&b, desc);
        if !elem::values_in_range(desc, &requested) { return err(Errno::Einval); }
        let mut previous = [0i64; MAX_ELEM_CHANNELS];
        let had_previous = (desc.ops.get)(owner, desc.private, &mut previous);
        if !(desc.ops.put)(owner, desc.private, &requested) { return err(Errno::Eio); }
        write_id(&b, 0, numid, &desc.id);
        let count = (desc.count as usize).min(MAX_ELEM_CHANNELS);
        let changed = !had_previous || previous[..count] != requested[..count];
        if changed { crate::control::notify_elem(owner, numid, &desc.id); }
        i64::from(changed)
    });
    found.unwrap_or_else(|| err(Errno::Enoent))
}

/// SNDRV_CTL_IOCTL_TLV_READ. # C: O(elements)
pub(crate) fn tlv_read(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let header = match UserBuf::new(arg, CTL_TLV_HEADER_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let numid = header.r32(CTL_TLV_NUMID);
    let length = header.r32(CTL_TLV_LENGTH) as usize;
    if numid == 0 { return err(Errno::Einval); }
    let found = elem::with_id(owner, numid, &ElemId::mixer(b"", 0), |_, desc| {
        let Some(scale) = desc.tlv else { return err(Errno::Enxio); };
        if desc.access & CTL_ELEM_ACCESS_TLV_READ == 0 { return err(Errno::Enxio); }
        let words = elem::db_scale_words(&scale);
        let bytes = words.len() * core::mem::size_of::<u32>();
        if length < bytes { return err(Errno::Enomem); }
        let body = match UserBuf::new(arg, CTL_TLV_DATA + bytes) { Some(b) => b, None => return err(Errno::Efault) };
        for (index, word) in words.iter().enumerate() {
            body.w32(CTL_TLV_DATA + index * core::mem::size_of::<u32>(), *word);
        }
        0
    });
    found.unwrap_or_else(|| err(Errno::Enoent))
}
