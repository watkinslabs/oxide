// ALSA control nodes (/dev/snd/controlC<N>) — SNDRV_CTL_IOCTL_*. Report the
// card identity + enumerates its one PCM playback device. The virtio-snd
// device offers no control elements unless VIRTIO_SND_F_CTLS is negotiated
// (config.controls), so ELEM_LIST honestly reports zero — not a stub.

use syscall::errno::Errno;

use crate::uapi::*;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Handle one `SNDRV_CTL_IOCTL_*` (magic 'U' stripped → `nr`). # C: O(1)
pub fn handle(owner: u32, card: u32, nr: u64, arg: u64) -> i64 {
    if crate::ops::ops_for(owner).is_none() {
        return err(Errno::Enodev);
    }
    match nr {
        CTL_PVERSION => match UserBuf::new(arg, 4) {
            Some(b) => { b.w32(0, SNDRV_CTL_VERSION); 0 } None => err(Errno::Efault),
        },
        CTL_CARD_INFO => card_info(card, arg),
        CTL_PCM_NEXT_DEVICE => pcm_next_device(arg),
        CTL_PCM_INFO => pcm_info(card, arg),
        CTL_ELEM_LIST => elem_list(arg),
        CTL_SUBSCRIBE => 0, // no async control events (no control elements)
        CTL_ELEM_INFO | CTL_ELEM_READ | CTL_ELEM_WRITE => err(Errno::Enoent),
        _ => err(Errno::Enotty),
    }
}

fn card_info(card: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CARD_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    b.zero(0, CARD_INFO_SIZE);
    b.w32(CI_CARD, card);
    b.wstr(CI_ID, b"virtio-snd", 16);
    b.wstr(CI_DRIVER, b"virtio_snd", 16);
    b.wstr(CI_NAME, b"virtio-snd", 32);
    b.wstr(CI_LONGNAME, b"virtio sound card at virtio bus", 80);
    b.wstr(CI_MIXERNAME, b"virtio-snd", 80);
    b.wstr(CI_COMPONENTS, b"", 128);
    0
}

/// SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE: given a starting device number, return
/// the next existing one (or -1). We have exactly device 0 (playback).
fn pcm_next_device(arg: u64) -> i64 {
    let b = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
    let from = b.r32(0) as i32;
    let next: i32 = if from <= 0 { 0 } else { -1 };
    b.w32(0, next as u32);
    0
}

/// SNDRV_CTL_IOCTL_PCM_INFO: fill snd_pcm_info for the device/stream selected
/// in the struct's `device`/`stream` fields. Only device 0 / playback exists.
fn pcm_info(card: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, PCM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let device = b.r32(PI_DEVICE);
    let stream = b.r32(PI_STREAM) as i32;
    if device != 0 || stream != STREAM_PLAYBACK { return err(Errno::Enoent); }
    b.zero(0, PCM_INFO_SIZE);
    b.w32(PI_DEVICE, 0);
    b.w32(PI_SUBDEVICE, 0);
    b.w32(PI_STREAM, STREAM_PLAYBACK as u32);
    b.w32(PI_CARD, card);
    b.wstr(PI_ID, b"virtio-snd", 64);
    b.wstr(PI_NAME, b"virtio-snd PCM", 80);
    b.wstr(PI_SUBNAME, b"subdevice #0", 32);
    b.w32(PI_SUBDEVICES_COUNT, 1);
    b.w32(PI_SUBDEVICES_AVAIL, 1);
    0
}

/// SNDRV_CTL_IOCTL_ELEM_LIST: zero control elements (no VIRTIO_SND_F_CTLS).
/// snd_ctl_elem_list: offset@0, space@4, used@8, count@12.
fn elem_list(arg: u64) -> i64 {
    let b = match UserBuf::new(arg, 16) { Some(b) => b, None => return err(Errno::Efault) };
    b.w32(8, 0);  // used
    b.w32(12, 0); // count
    0
}
