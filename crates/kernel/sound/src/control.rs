// ALSA control nodes (/dev/snd/controlC<N>) — SNDRV_CTL_IOCTL_*. Report the
// card identity, enumerate PCM devices, and expose the static Linux mixer
// controls promised by docs/58 when the device has no virtio CTL table.

use alloc::vec::Vec;
use syscall::errno::Errno;
use sync::{Spinlock, TaskList as SoundControlLockClass};

use crate::uapi::*;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

const MASTER_VOL_NUMID: u32 = 1;
const MASTER_SW_NUMID: u32 = 2;
const MASTER_VOL_NAME: &[u8] = b"Master Playback Volume";
const MASTER_SW_NAME: &[u8] = b"Master Playback Switch";
const STATIC_ELEM_COUNT: u32 = 2;

#[derive(Clone, Copy)]
struct MixerState {
    owner: u32,
    volume: [u32; 2],
    enabled: [bool; 2],
    subscribed: bool,
}

static MIXERS: Spinlock<Vec<MixerState>, SoundControlLockClass> = Spinlock::new(Vec::new());

fn state(owner: u32) -> MixerState {
    let mut mixers = MIXERS.lock();
    if let Some(mixer) = mixers.iter().find(|mixer| mixer.owner == owner).copied() {
        return mixer;
    }
    let mixer = MixerState {
        owner,
        volume: [75, 75],
        enabled: [true, true],
        subscribed: false,
    };
    mixers.push(mixer);
    mixer
}

fn update_state(owner: u32, f: impl FnOnce(&mut MixerState)) -> bool {
    let mut mixers = MIXERS.lock();
    if mixers.iter().all(|mixer| mixer.owner != owner) {
        mixers.push(MixerState {
            owner,
            volume: [75, 75],
            enabled: [true, true],
            subscribed: false,
        });
    }
    let Some(mixer) = mixers.iter_mut().find(|mixer| mixer.owner == owner) else {
        return false;
    };
    f(mixer);
    true
}

/// Owner-keyed OSS mixer read/write bridge. Values use OSS's packed
/// left|right<<8 0..100 percentage convention.
pub fn mixer_level(owner: u32) -> Option<u32> {
    if crate::ops::ops_for(owner).is_none() {
        return None;
    }
    let mixer = state(owner);
    Some(mixer.volume[0].min(100) | (mixer.volume[1].min(100) << 8))
}

pub fn set_mixer_level(owner: u32, packed: u32) -> bool {
    if crate::ops::ops_for(owner).is_none() {
        return false;
    }
    let left = (packed & 0xff).min(100);
    let right = ((packed >> 8) & 0xff).min(100);
    update_state(owner, |mixer| mixer.volume = [left, right])
}

/// Drop card-local ALSA/OSS control state when the owning sound card is
/// removed or probe publication rolls back.
pub(crate) fn unregister_card(owner: u32) {
    MIXERS.lock().retain(|mixer| mixer.owner != owner);
}

fn write_elem_id(buf: &UserBuf, off: usize, numid: u32, name: &[u8]) {
    buf.zero(off, CTL_ELEM_ID_SIZE);
    buf.w32(off + CEI_NUMID, numid);
    buf.w32(off + CEI_IFACE, CTL_ELEM_IFACE_MIXER);
    buf.w32(off + CEI_DEVICE, 0);
    buf.w32(off + CEI_SUBDEVICE, 0);
    buf.wstr(off + CEI_NAME, name, CEI_NAME_LEN);
    buf.w32(off + CEI_INDEX, 0);
}

fn elem_name_matches(buf: &UserBuf, name: &[u8]) -> bool {
    for i in 0..CEI_NAME_LEN {
        let got = buf.r8(CEI_NAME + i);
        let want = *name.get(i).unwrap_or(&0);
        if got != want {
            return false;
        }
        if got == 0 {
            return true;
        }
    }
    name.len() >= CEI_NAME_LEN
}

fn elem_numid(buf: &UserBuf) -> Option<u32> {
    match buf.r32(CEI_NUMID) {
        MASTER_VOL_NUMID => Some(MASTER_VOL_NUMID),
        MASTER_SW_NUMID => Some(MASTER_SW_NUMID),
        0 if buf.r32(CEI_IFACE) == CTL_ELEM_IFACE_MIXER && elem_name_matches(buf, MASTER_VOL_NAME) => {
            Some(MASTER_VOL_NUMID)
        }
        0 if buf.r32(CEI_IFACE) == CTL_ELEM_IFACE_MIXER && elem_name_matches(buf, MASTER_SW_NAME) => {
            Some(MASTER_SW_NUMID)
        }
        _ => None,
    }
}

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
        CTL_PCM_NEXT_DEVICE => pcm_next_device(owner, arg),
        CTL_PCM_INFO => pcm_info(owner, card, arg),
        CTL_ELEM_LIST => elem_list(arg),
        CTL_SUBSCRIBE => subscribe(owner, arg),
        CTL_ELEM_INFO => elem_info(arg),
        CTL_ELEM_READ => elem_read(owner, arg),
        CTL_ELEM_WRITE => elem_write(owner, arg),
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
/// the next existing one (or -1). ALSA device 0 exists when the card has
/// either playback or capture caps registered.
fn pcm_next_device(owner: u32, arg: u64) -> i64 {
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
fn pcm_info(owner: u32, card: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, PCM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let device = b.r32(PI_DEVICE);
    let stream = b.r32(PI_STREAM) as i32;
    let available = match stream {
        STREAM_PLAYBACK => crate::ops::pcm_caps(owner).is_some(),
        STREAM_CAPTURE => crate::ops::cap_caps(owner).is_some(),
        _ => false,
    };
    if device != 0 || !available { return err(Errno::Enoent); }
    b.zero(0, PCM_INFO_SIZE);
    b.w32(PI_DEVICE, 0);
    b.w32(PI_SUBDEVICE, 0);
    b.w32(PI_STREAM, stream as u32);
    b.w32(PI_CARD, card);
    b.wstr(PI_ID, b"virtio-snd", 64);
    let name = if stream == STREAM_CAPTURE { b"virtio-snd PCM Capture".as_slice() } else { b"virtio-snd PCM Playback".as_slice() };
    b.wstr(PI_NAME, name, 80);
    b.wstr(PI_SUBNAME, b"subdevice #0", 32);
    b.w32(PI_SUBDEVICES_COUNT, 1);
    b.w32(PI_SUBDEVICES_AVAIL, 1);
    0
}

/// SNDRV_CTL_IOCTL_ELEM_LIST: expose static master volume/switch elements
/// when no device-backed VIRTIO_SND_F_CTLS table is present.
/// snd_ctl_elem_list: offset@0, space@4, used@8, count@12.
fn elem_list(arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_LIST_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let offset = b.r32(CEL_OFFSET).min(STATIC_ELEM_COUNT);
    let space = b.r32(CEL_SPACE);
    let used = (STATIC_ELEM_COUNT - offset).min(space);
    b.w32(CEL_USED, used);
    b.w32(CEL_COUNT, STATIC_ELEM_COUNT);
    if used == 0 {
        return 0;
    }
    let pids = b.r64(CEL_PIDS);
    let Some(bytes) = (used as usize).checked_mul(CTL_ELEM_ID_SIZE) else {
        return err(Errno::Einval);
    };
    let ids = match UserBuf::new(pids, bytes) {
        Some(ids) => ids,
        None => return err(Errno::Efault),
    };
    for n in 0..used {
        let off = (n as usize) * CTL_ELEM_ID_SIZE;
        match offset + n {
            0 => write_elem_id(&ids, off, MASTER_VOL_NUMID, MASTER_VOL_NAME),
            1 => write_elem_id(&ids, off, MASTER_SW_NUMID, MASTER_SW_NAME),
            _ => {}
        }
    }
    0
}

fn elem_info(arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let Some(numid) = elem_numid(&b) else {
        return err(Errno::Enoent);
    };
    b.zero(CEINFO_TYPE, CTL_ELEM_INFO_SIZE - CEINFO_TYPE);
    match numid {
        MASTER_VOL_NUMID => {
            write_elem_id(&b, 0, MASTER_VOL_NUMID, MASTER_VOL_NAME);
            b.w32(CEINFO_TYPE, CTL_ELEM_TYPE_INTEGER);
            b.w32(CEINFO_ACCESS, CTL_ELEM_ACCESS_READWRITE);
            b.w32(CEINFO_COUNT, 2);
            b.w32(CEINFO_OWNER, 0);
            b.w64(CEINFO_INTEGER_MIN, 0);
            b.w64(CEINFO_INTEGER_MAX, 100);
            b.w64(CEINFO_INTEGER_STEP, 1);
            0
        }
        MASTER_SW_NUMID => {
            write_elem_id(&b, 0, MASTER_SW_NUMID, MASTER_SW_NAME);
            b.w32(CEINFO_TYPE, CTL_ELEM_TYPE_BOOLEAN);
            b.w32(CEINFO_ACCESS, CTL_ELEM_ACCESS_READWRITE);
            b.w32(CEINFO_COUNT, 2);
            b.w32(CEINFO_OWNER, 0);
            b.w64(CEINFO_INTEGER_MIN, 0);
            b.w64(CEINFO_INTEGER_MAX, 1);
            b.w64(CEINFO_INTEGER_STEP, 1);
            0
        }
        _ => err(Errno::Enoent),
    }
}

fn elem_read(owner: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_VALUE_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let Some(numid) = elem_numid(&b) else {
        return err(Errno::Enoent);
    };
    let mixer = state(owner);
    match numid {
        MASTER_VOL_NUMID => {
            write_elem_id(&b, 0, MASTER_VOL_NUMID, MASTER_VOL_NAME);
            b.w64(CEV_VALUE, mixer.volume[0].min(100) as u64);
            b.w64(CEV_VALUE + 8, mixer.volume[1].min(100) as u64);
            0
        }
        MASTER_SW_NUMID => {
            write_elem_id(&b, 0, MASTER_SW_NUMID, MASTER_SW_NAME);
            b.w64(CEV_VALUE, mixer.enabled[0] as u64);
            b.w64(CEV_VALUE + 8, mixer.enabled[1] as u64);
            0
        }
        _ => err(Errno::Enoent),
    }
}

fn elem_write(owner: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_VALUE_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    let Some(numid) = elem_numid(&b) else {
        return err(Errno::Enoent);
    };
    match numid {
        MASTER_VOL_NUMID => {
            let left = b.r64(CEV_VALUE).min(100) as u32;
            let right = b.r64(CEV_VALUE + 8).min(100) as u32;
            if !update_state(owner, |mixer| mixer.volume = [left, right]) {
                return err(Errno::Enodev);
            }
            write_elem_id(&b, 0, MASTER_VOL_NUMID, MASTER_VOL_NAME);
            0
        }
        MASTER_SW_NUMID => {
            let left = b.r64(CEV_VALUE) != 0;
            let right = b.r64(CEV_VALUE + 8) != 0;
            if !update_state(owner, |mixer| mixer.enabled = [left, right]) {
                return err(Errno::Enodev);
            }
            write_elem_id(&b, 0, MASTER_SW_NUMID, MASTER_SW_NAME);
            0
        }
        _ => err(Errno::Enoent),
    }
}

fn subscribe(owner: u32, arg: u64) -> i64 {
    let b = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
    let enabled = b.r32(0) != 0;
    if !update_state(owner, |mixer| mixer.subscribed = enabled) {
        return err(Errno::Enodev);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(_owner: u32) -> Option<(u32, u32, u32, u32)> { Some((0, 0, 0, 0)) }
    fn caps(_owner: u32) -> crate::ops::Caps { Some((0, 0, 1, 2)) }
    fn period(_owner: u32) -> usize { 2048 }
    fn hw_params(_owner: u32, _rate: u8, _format: u8, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool { true }
    fn yes(_owner: u32) -> bool { true }
    fn trigger(_owner: u32, _start: bool) -> bool { true }
    fn submit(_owner: u32, b: &[u8]) -> usize { b.len() }
    fn recv(_owner: u32, b: &mut [u8]) -> usize { b.len() }

    static TEST_OPS: crate::ops::SoundOps = crate::ops::SoundOps {
        config: cfg,
        pcm_caps: caps,
        cap_caps: caps,
        period_bytes: period,
        pcm_hw_params: hw_params,
        pcm_prepare: yes,
        pcm_trigger: trigger,
        pcm_hw_free: yes,
        pcm_submit: submit,
        cap_hw_params: hw_params,
        cap_prepare: yes,
        cap_trigger: trigger,
        cap_hw_free: yes,
        pcm_recv: recv,
    };

    fn u32_at(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    fn u64_at(buf: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_id(buf: &mut [u8], numid: u32) {
        put_u32(buf, CEI_NUMID, numid);
        put_u32(buf, CEI_IFACE, CTL_ELEM_IFACE_MIXER);
    }

    #[test]
    fn control_pcm_info_reports_playback_and_capture_streams() {
        let owner = 0x5102;
        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
        assert!(crate::reserve_card(owner));
        assert!(crate::ops::register(owner, &TEST_OPS));

        let mut info = [0u8; PCM_INFO_SIZE];
        put_u32(&mut info, PI_DEVICE, 0);
        put_u32(&mut info, PI_STREAM, STREAM_PLAYBACK as u32);
        assert_eq!(handle(owner, 3, CTL_PCM_INFO, info.as_mut_ptr() as u64), 0);
        assert_eq!(u32_at(&info, PI_DEVICE), 0);
        assert_eq!(u32_at(&info, PI_STREAM), STREAM_PLAYBACK as u32);
        assert_eq!(u32_at(&info, PI_CARD), 3);

        info.fill(0);
        put_u32(&mut info, PI_DEVICE, 0);
        put_u32(&mut info, PI_STREAM, STREAM_CAPTURE as u32);
        assert_eq!(handle(owner, 3, CTL_PCM_INFO, info.as_mut_ptr() as u64), 0);
        assert_eq!(u32_at(&info, PI_DEVICE), 0);
        assert_eq!(u32_at(&info, PI_STREAM), STREAM_CAPTURE as u32);
        assert_eq!(u32_at(&info, PI_CARD), 3);

        info.fill(0);
        put_u32(&mut info, PI_DEVICE, 0);
        put_u32(&mut info, PI_STREAM, 99);
        assert_eq!(
            handle(owner, 3, CTL_PCM_INFO, info.as_mut_ptr() as u64),
            -(Errno::Enoent.as_i32() as i64)
        );

        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
    }

    #[test]
    fn static_master_controls_are_listed_and_described() {
        let owner = 0x5100;
        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
        assert!(crate::reserve_card(owner));
        assert!(crate::ops::register(owner, &TEST_OPS));

        let mut ids = [0u8; CTL_ELEM_ID_SIZE * STATIC_ELEM_COUNT as usize];
        let mut list = [0u8; CTL_ELEM_LIST_SIZE];
        put_u32(&mut list, CEL_SPACE, STATIC_ELEM_COUNT);
        put_u64(&mut list, CEL_PIDS, ids.as_mut_ptr() as u64);

        assert_eq!(handle(owner, 0, CTL_ELEM_LIST, list.as_mut_ptr() as u64), 0);
        assert_eq!(u32_at(&list, CEL_USED), STATIC_ELEM_COUNT);
        assert_eq!(u32_at(&list, CEL_COUNT), STATIC_ELEM_COUNT);
        assert_eq!(u32_at(&ids, CEI_NUMID), MASTER_VOL_NUMID);
        assert_eq!(u32_at(&ids, CTL_ELEM_ID_SIZE + CEI_NUMID), MASTER_SW_NUMID);

        let mut info = [0u8; CTL_ELEM_INFO_SIZE];
        put_id(&mut info, MASTER_VOL_NUMID);
        assert_eq!(handle(owner, 0, CTL_ELEM_INFO, info.as_mut_ptr() as u64), 0);
        assert_eq!(u32_at(&info, CEINFO_TYPE), CTL_ELEM_TYPE_INTEGER);
        assert_eq!(u32_at(&info, CEINFO_ACCESS), CTL_ELEM_ACCESS_READWRITE);
        assert_eq!(u32_at(&info, CEINFO_COUNT), 2);
        assert_eq!(u64_at(&info, CEINFO_INTEGER_MAX), 100);

        info.fill(0);
        put_id(&mut info, MASTER_SW_NUMID);
        assert_eq!(handle(owner, 0, CTL_ELEM_INFO, info.as_mut_ptr() as u64), 0);
        assert_eq!(u32_at(&info, CEINFO_TYPE), CTL_ELEM_TYPE_BOOLEAN);
        assert_eq!(u64_at(&info, CEINFO_INTEGER_MAX), 1);

        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
    }

    #[test]
    fn static_master_controls_round_trip_and_back_oss_mixer() {
        let owner = 0x5101;
        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
        assert!(crate::reserve_card(owner));
        assert!(crate::ops::register(owner, &TEST_OPS));

        let mut value = [0u8; CTL_ELEM_VALUE_SIZE];
        put_id(&mut value, MASTER_VOL_NUMID);
        put_u64(&mut value, CEV_VALUE, 30);
        put_u64(&mut value, CEV_VALUE + 8, 40);
        assert_eq!(handle(owner, 0, CTL_ELEM_WRITE, value.as_mut_ptr() as u64), 0);

        value.fill(0);
        put_id(&mut value, MASTER_VOL_NUMID);
        assert_eq!(handle(owner, 0, CTL_ELEM_READ, value.as_mut_ptr() as u64), 0);
        assert_eq!(u64_at(&value, CEV_VALUE), 30);
        assert_eq!(u64_at(&value, CEV_VALUE + 8), 40);

        assert_eq!(mixer_level(owner), Some(30 | (40 << 8)));
        assert!(set_mixer_level(owner, 80 | (90 << 8)));

        value.fill(0);
        put_id(&mut value, MASTER_VOL_NUMID);
        assert_eq!(handle(owner, 0, CTL_ELEM_READ, value.as_mut_ptr() as u64), 0);
        assert_eq!(u64_at(&value, CEV_VALUE), 80);
        assert_eq!(u64_at(&value, CEV_VALUE + 8), 90);

        let read_req = (2u64 << 30) | (4u64 << 16) | ((b'M' as u64) << 8);
        let write_req = (1u64 << 30) | (4u64 << 16) | ((b'M' as u64) << 8);
        let mut packed = 10u32 | (20u32 << 8);
        assert_eq!(crate::oss::handle(owner, true, read_req, (&mut packed as *mut u32) as u64), 0);
        assert_eq!(packed, 80 | (90 << 8), "read must not consume the caller's input value as a write");
        packed = 10 | (20 << 8);
        assert_eq!(crate::oss::handle(owner, true, write_req, (&mut packed as *mut u32) as u64), 0);
        assert_eq!(packed, 10 | (20 << 8));

        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
    }
}
