// Control-element registry: the card driver's mixer/jack controls, keyed by
// card owner, numbered the way ALSA numbers them (numid allocated in
// registration order starting at 1 per card). The core never invents an
// element; it only publishes what a driver registered.

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as ElemLockClass};

use crate::uapi::*;

/// Widest control this core carries values for (ALSA allows 128; HDA-class
/// mixer elements are mono or stereo).
pub const MAX_ELEM_CHANNELS: usize = 8;
/// `snd_ctl_elem_id.name` capacity.
pub const ELEM_NAME_WIDTH: usize = CEI_NAME_LEN;
/// `snd_ctl_elem_info.value.enumerated.name` capacity.
pub const ENUM_NAME_WIDTH: usize = CEINFO_ENUM_NAME_LEN;

/// Values carried across the driver boundary for one element.
pub type ElemValues = [i64; MAX_ELEM_CHANNELS];

/// dB mapping published through SNDRV_CTL_IOCTL_TLV_READ as a DB_SCALE entry.
#[derive(Copy, Clone)]
pub struct DbScale {
    /// Gain at the minimum step, in 1/100 dB.
    pub min_centibel: i32,
    /// Gain per step, in 1/100 dB.
    pub step_centibel: u32,
    /// Minimum step is a hard mute.
    pub mute: bool,
}

#[derive(Copy, Clone)]
pub struct ElemId {
    pub iface: u32,
    pub device: u32,
    pub subdevice: u32,
    pub name: [u8; ELEM_NAME_WIDTH],
    pub index: u32,
}

impl ElemId {
    /// Mixer-interface element with the given name and index. # C: O(name)
    pub fn mixer(name: &[u8], index: u32) -> Self {
        let mut padded = [0u8; ELEM_NAME_WIDTH];
        let n = if name.len() < ELEM_NAME_WIDTH { name.len() } else { ELEM_NAME_WIDTH };
        padded[..n].copy_from_slice(&name[..n]);
        Self { iface: CTL_ELEM_IFACE_MIXER, device: 0, subdevice: 0, name: padded, index }
    }

    /// Does this id name the same element as `other`? # C: O(name)
    pub fn same(&self, other: &ElemId) -> bool {
        self.iface == other.iface && self.device == other.device
            && self.subdevice == other.subdevice && self.index == other.index
            && self.name == other.name
    }
}

/// Driver-side accessors for one element's value.
pub struct ElemOps {
    pub get: fn(crate::SoundOwnerKey, u32, &mut ElemValues) -> bool,
    pub put: fn(crate::SoundOwnerKey, u32, &ElemValues) -> bool,
    /// Enumerated item name; `false` when `item` is out of range.
    pub enum_name: fn(crate::SoundOwnerKey, u32, u32, &mut [u8; ENUM_NAME_WIDTH]) -> bool,
}

/// One registered control element.
pub struct ElemDesc {
    pub id: ElemId,
    pub etype: u32,
    pub access: u32,
    /// Channel count (`snd_ctl_elem_info.count`).
    pub count: u32,
    pub min: i64,
    pub max: i64,
    pub step: i64,
    /// Enumerated item count; ignored for other types.
    pub items: u32,
    pub tlv: Option<DbScale>,
    /// Driver-private discriminator handed back to every op.
    pub private: u32,
    pub ops: &'static ElemOps,
}

struct Entry {
    owner: crate::SoundOwnerKey,
    numid: u32,
    desc: ElemDesc,
}

static ELEMS: Spinlock<Vec<Entry>, ElemLockClass> = Spinlock::new(Vec::new());

/// Register one control element for `owner`, returning its numid. A repeat
/// registration of the same id replaces the description in place, so a
/// re-probe cannot grow a second element with the same name.
/// # C: O(elements)
pub fn register(owner: crate::SoundOwnerKey, desc: ElemDesc) -> u32 {
    let mut guard = ELEMS.lock();
    if let Some(entry) = guard.iter_mut().find(|entry| entry.owner == owner && entry.desc.id.same(&desc.id)) {
        entry.desc = desc;
        return entry.numid;
    }
    let numid = guard.iter().filter(|entry| entry.owner == owner).count() as u32 + 1;
    guard.push(Entry { owner, numid, desc });
    numid
}

/// Drop every element belonging to `owner`. # C: O(elements)
pub fn unregister_card(owner: crate::SoundOwnerKey) {
    ELEMS.lock().retain(|entry| entry.owner != owner);
}

/// Number of elements registered for `owner`. # C: O(elements)
pub fn count(owner: crate::SoundOwnerKey) -> u32 {
    ELEMS.lock().iter().filter(|entry| entry.owner == owner).count() as u32
}

/// Run `f` over the `n`th element of `owner` in numid order. # C: O(elements)
pub fn with_nth<R>(owner: crate::SoundOwnerKey, n: u32, f: impl FnOnce(u32, &ElemDesc) -> R) -> Option<R> {
    let guard = ELEMS.lock();
    let entry = guard.iter().filter(|entry| entry.owner == owner).nth(n as usize)?;
    Some(f(entry.numid, &entry.desc))
}

/// Run `f` over the element selected by numid, or by full id when `numid`
/// is zero — the lookup rule ALSA's control core applies. # C: O(elements)
pub fn with_id<R>(owner: crate::SoundOwnerKey, numid: u32, id: &ElemId,
                  f: impl FnOnce(u32, &ElemDesc) -> R) -> Option<R> {
    let guard = ELEMS.lock();
    let entry = guard.iter().find(|entry| {
        entry.owner == owner && if numid != 0 { entry.numid == numid } else { entry.desc.id.same(id) }
    })?;
    Some(f(entry.numid, &entry.desc))
}

/// Clamp `values[..count]` into the element's declared range. # C: O(count)
pub fn clamp_values(desc: &ElemDesc, values: &mut ElemValues) {
    let (lo, hi) = match desc.etype {
        CTL_ELEM_TYPE_BOOLEAN => (0, 1),
        CTL_ELEM_TYPE_ENUMERATED => (0, desc.items.saturating_sub(1) as i64),
        _ => (desc.min, desc.max),
    };
    let count = (desc.count as usize).min(MAX_ELEM_CHANNELS);
    for value in values.iter_mut().take(count) {
        if *value < lo { *value = lo; }
        if *value > hi { *value = hi; }
    }
}

/// Are `values[..count]` inside the element's declared range? A write that
/// fails this is EINVAL, matching ALSA's range check.
/// # C: O(count)
pub fn values_in_range(desc: &ElemDesc, values: &ElemValues) -> bool {
    let (lo, hi) = match desc.etype {
        CTL_ELEM_TYPE_BOOLEAN => (0, 1),
        CTL_ELEM_TYPE_ENUMERATED => (0, desc.items.saturating_sub(1) as i64),
        _ => (desc.min, desc.max),
    };
    let count = (desc.count as usize).min(MAX_ELEM_CHANNELS);
    values.iter().take(count).all(|value| *value >= lo && *value <= hi)
}

/// DB_SCALE TLV words `[type, byte_len, min_centibel, step|mute]`. # C: O(1)
pub fn db_scale_words(scale: &DbScale) -> [u32; 4] {
    let mut step = scale.step_centibel;
    if scale.mute { step |= CTL_TLV_DB_SCALE_MUTE; }
    [CTL_TLVT_DB_SCALE, 2 * core::mem::size_of::<u32>() as u32, scale.min_centibel as u32, step]
}

#[cfg(test)]
#[path = "tests/elem.rs"]
mod tests;
