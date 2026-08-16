// ALSA control nodes (/dev/snd/controlC<N>) — SNDRV_CTL_IOCTL_*. Card
// identity, PCM device enumeration, and the driver-registered mixer/jack
// elements. Every element and every string comes from the card driver; this
// core invents neither.
//
// Module manifest:
// - `control_elem`: ELEM_LIST/INFO/READ/WRITE and TLV_READ marshalling.
// - `control_event`: the per-card event queue behind SUBSCRIBE_EVENTS.

use syscall::errno::Errno;

use crate::elem::{ElemId, MAX_ELEM_CHANNELS};
use crate::identity::{pcm_stream_name, write_card_info};
use crate::uapi::*;

#[path = "control_elem.rs"] mod control_elem;
#[path = "control_event.rs"] pub mod events;

/// Element name the OSS `/dev/mixer` bridge maps its master channel onto.
const OSS_MASTER_NAME: &[u8] = b"Master Playback Volume";
/// OSS mixer levels are percentages.
const OSS_LEVEL_MAX: i64 = 100;
/// Bit position of the right channel in an OSS packed stereo level.
const OSS_RIGHT_SHIFT: u32 = 8;
const OSS_CHANNEL_MASK: u32 = 0xFF;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Queue an element-value notification for every control-fd subscriber.
/// # C: O(cards)
pub(crate) fn notify_elem(owner: crate::SoundOwnerKey, numid: u32, id: &ElemId) {
    events::push(owner, CTL_EVENT_MASK_VALUE, numid, id);
    crate::device::wake_control(owner);
}

/// Publish a jack/element change from a card driver (unsolicited codec event
/// or a driver-side state change userspace must observe). # C: O(cards)
pub fn notify(owner: crate::SoundOwnerKey, numid: u32, id: &ElemId) {
    notify_elem(owner, numid, id);
}

/// Scale a driver element value onto the OSS 0..100 percentage. # C: O(1)
fn to_percent(value: i64, min: i64, max: i64) -> u32 {
    if max <= min { return 0; }
    (((value - min) * OSS_LEVEL_MAX) / (max - min)).clamp(0, OSS_LEVEL_MAX) as u32
}

/// Inverse of [`to_percent`]. # C: O(1)
fn from_percent(percent: u32, min: i64, max: i64) -> i64 {
    if max <= min { return min; }
    min + ((percent.min(OSS_LEVEL_MAX as u32) as i64) * (max - min) + OSS_LEVEL_MAX / 2) / OSS_LEVEL_MAX
}

/// Owner-keyed OSS mixer bridge over the card's master element. No mixer
/// exists until a driver registers real controls.
pub fn mixer_level(owner: crate::SoundOwnerKey) -> Option<u32> {
    crate::elem::with_id(owner, 0, &ElemId::mixer(OSS_MASTER_NAME, 0), |_, desc| {
        let mut values = [0i64; MAX_ELEM_CHANNELS];
        if !(desc.ops.get)(owner, desc.private, &mut values) { return None; }
        let left = to_percent(values[0], desc.min, desc.max);
        let right = if desc.count > 1 { to_percent(values[1], desc.min, desc.max) } else { left };
        Some(left | (right << OSS_RIGHT_SHIFT))
    })?
}

pub fn set_mixer_level(owner: crate::SoundOwnerKey, packed: u32) -> bool {
    crate::elem::with_id(owner, 0, &ElemId::mixer(OSS_MASTER_NAME, 0), |numid, desc| {
        let mut values = [0i64; MAX_ELEM_CHANNELS];
        values[0] = from_percent(packed & OSS_CHANNEL_MASK, desc.min, desc.max);
        values[1] = from_percent((packed >> OSS_RIGHT_SHIFT) & OSS_CHANNEL_MASK, desc.min, desc.max);
        let left = values[0];
        for value in values.iter_mut().skip(2) { *value = left; }
        if !(desc.ops.put)(owner, desc.private, &values) { return false; }
        notify_elem(owner, numid, &desc.id);
        true
    }).unwrap_or(false)
}

/// Drop card-local ALSA/OSS control state when the owning sound card is
/// removed or probe publication rolls back.
pub(crate) fn unregister_card(owner: crate::SoundOwnerKey) {
    crate::elem::unregister_card(owner);
    events::unregister_card(owner);
}

/// Handle one `SNDRV_CTL_IOCTL_*` (magic 'U' stripped → `nr`). # C: O(1)
#[cfg(test)]
pub fn handle(owner: crate::SoundOwnerKey, card: u32, nr: u64, arg: u64) -> i64 {
    handle_open(owner, card, None, nr, arg)
}

/// File-carrying control dispatch. ALSA subscription is state of the open
/// description (`snd_ctl_file`), so dup shares it and a separate open does
/// not. All other control commands retain their card-owned semantics.
/// # C: O(1)
pub(crate) fn handle_open(
    owner: crate::SoundOwnerKey,
    card: u32,
    file: Option<&vfs::File>,
    nr: u64,
    arg: u64,
) -> i64 {
    if crate::ops::ops_for(owner).is_none() {
        return err(Errno::Enodev);
    }
    match nr {
        CTL_PVERSION => match UserBuf::new(arg, 4) {
            Some(b) => { b.w32(0, SNDRV_CTL_VERSION); 0 } None => err(Errno::Efault),
        },
        CTL_CARD_INFO => card_info(owner, card, arg),
        CTL_PCM_NEXT_DEVICE => pcm_next_device(owner, arg),
        CTL_PCM_INFO => pcm_info(owner, card, arg),
        CTL_ELEM_LIST => control_elem::list(owner, arg),
        CTL_SUBSCRIBE => match file {
            Some(file) => subscribe(owner, file, arg),
            None => err(Errno::Ebadfd),
        },
        CTL_ELEM_INFO => control_elem::info(owner, arg),
        CTL_ELEM_READ => control_elem::read(owner, arg),
        CTL_ELEM_WRITE => control_elem::write(owner, arg),
        CTL_TLV_READ => control_elem::tlv_read(owner, arg),
        _ => err(Errno::Enotty),
    }
}

fn card_info(owner: crate::SoundOwnerKey, card: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CARD_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let Some(ident) = crate::ops::identity(owner) else { return err(Errno::Enodev); };
    write_card_info(&b, card, &ident);
    0
}

/// SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE: given a starting device number, return
/// the next existing one (or -1). ALSA device 0 exists when the card has
/// either playback or capture caps registered.
fn pcm_next_device(owner: crate::SoundOwnerKey, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
    let from = b.r32(0) as i32;
    let has_device = crate::ops::pcm_caps(owner).is_some() || crate::ops::cap_caps(owner).is_some();
    let next: i32 = if has_device && from <= 0 { 0 } else { -1 };
    b.w32(0, next as u32);
    0
}

/// SNDRV_CTL_IOCTL_PCM_INFO: fill snd_pcm_info for the device/stream selected
/// in the struct's `device`/`stream` fields. Device 0 exposes the playback
/// and capture streams that the registered card ops report.
fn pcm_info(owner: crate::SoundOwnerKey, card: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, PCM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let device = b.r32(PI_DEVICE);
    let stream = b.r32(PI_STREAM) as i32;
    let available = match stream {
        STREAM_PLAYBACK => crate::ops::pcm_caps(owner).is_some(),
        STREAM_CAPTURE => crate::ops::cap_caps(owner).is_some(),
        _ => false,
    };
    if device != 0 || !available { return err(Errno::Enoent); }
    let Some(ident) = crate::ops::identity(owner) else { return err(Errno::Enodev); };
    crate::pcm_info::write(&b, card, stream, &ident.id, &pcm_stream_name(&ident, stream == STREAM_CAPTURE));
    0
}

/// SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS. Reading back with a negative argument
/// reports the current subscription without changing it.
fn subscribe(owner: crate::SoundOwnerKey, file: &vfs::File, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
    let requested = b.r32(0) as i32;
    let (subscribed, cursor) = events::unpack(file.private_data());
    if requested < 0 {
        b.w32(0, u32::from(subscribed));
        return 0;
    }
    if requested != 0 {
        // Subscribing starts the reader at the current tail, so a late
        // subscriber never replays history it did not ask for.
        let start = if subscribed { cursor } else { events::latest_seq(owner) };
        file.set_private_data(events::pack(true, start));
    } else {
        file.set_private_data(events::pack(false, cursor));
    }
    0
}

/// Encode one queued event into a `snd_ctl_event` for `snd_ctl_read`, and
/// return the sequence the reader's cursor should advance to.
/// # C: O(CTL_EVENT_SIZE)
pub(crate) fn read_event(owner: crate::SoundOwnerKey, cursor: u64, out: &mut [u8]) -> Option<u64> {
    let event = events::next_after(owner, cursor)?;
    if out.len() < CTL_EVENT_SIZE { return None; }
    out[..CTL_EVENT_SIZE].fill(0);
    out[..4].copy_from_slice(&CTL_EVENT_ELEM.to_le_bytes());
    out[CTL_EVENT_MASK..CTL_EVENT_MASK + 4].copy_from_slice(&event.mask.to_le_bytes());
    let id = CTL_EVENT_ID;
    out[id + CEI_NUMID..id + CEI_NUMID + 4].copy_from_slice(&event.numid.to_le_bytes());
    out[id + CEI_IFACE..id + CEI_IFACE + 4].copy_from_slice(&event.id.iface.to_le_bytes());
    out[id + CEI_DEVICE..id + CEI_DEVICE + 4].copy_from_slice(&event.id.device.to_le_bytes());
    out[id + CEI_SUBDEVICE..id + CEI_SUBDEVICE + 4].copy_from_slice(&event.id.subdevice.to_le_bytes());
    out[id + CEI_NAME..id + CEI_NAME + CEI_NAME_LEN].copy_from_slice(&event.id.name);
    out[id + CEI_INDEX..id + CEI_INDEX + 4].copy_from_slice(&event.id.index.to_le_bytes());
    Some(event.seq)
}

#[cfg(test)]
#[path = "tests/control.rs"]
mod tests;
