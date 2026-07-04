// ALSA control nodes (/dev/snd/controlC<N>) — SNDRV_CTL_IOCTL_*. Report the
// card identity and enumerate PCM devices. Mixer/control elements must be
// backed by driver-visible controls; this core must not invent card controls.

use syscall::errno::Errno;

use crate::uapi::*;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Owner-keyed OSS mixer bridge. No mixer exists until a driver registers
/// real controls; report absence instead of fabricating a Master control.
pub fn mixer_level(owner: u32) -> Option<u32> {
    let _ = owner;
    None
}

pub fn set_mixer_level(owner: u32, packed: u32) -> bool {
    let _ = (owner, packed);
    false
}

/// Drop card-local ALSA/OSS control state when the owning sound card is
/// removed or probe publication rolls back.
pub(crate) fn unregister_card(owner: u32) {
    let _ = owner;
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

/// SNDRV_CTL_IOCTL_ELEM_LIST: expose no elements until the card driver
/// registers real mixer/control elements.
/// snd_ctl_elem_list: offset@0, space@4, used@8, count@12.
fn elem_list(arg: u64) -> i64 {
    let b = match UserBuf::new(arg, CTL_ELEM_LIST_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    b.w32(CEL_USED, 0);
    b.w32(CEL_COUNT, 0);
    0
}

fn elem_info(arg: u64) -> i64 {
    let _ = match UserBuf::new(arg, CTL_ELEM_INFO_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    err(Errno::Enoent)
}

fn elem_read(owner: u32, arg: u64) -> i64 {
    let _ = owner;
    let _ = match UserBuf::new(arg, CTL_ELEM_VALUE_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    err(Errno::Enoent)
}

fn elem_write(owner: u32, arg: u64) -> i64 {
    let _ = owner;
    let _ = match UserBuf::new(arg, CTL_ELEM_VALUE_SIZE) { Some(b) => b, None => return err(Errno::Efault) };
    err(Errno::Enoent)
}

fn subscribe(owner: u32, arg: u64) -> i64 {
    let _ = owner;
    let _ = match UserBuf::new(arg, 4) { Some(b) => b, None => return err(Errno::Efault) };
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
    fn missing_mixer_controls_are_not_fabricated() {
        let owner = 0x5100;
        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
        assert!(crate::reserve_card(owner));
        assert!(crate::ops::register(owner, &TEST_OPS));

        let mut ids = [0u8; CTL_ELEM_ID_SIZE * 2];
        let mut list = [0u8; CTL_ELEM_LIST_SIZE];
        put_u32(&mut list, CEL_SPACE, 2);
        put_u64(&mut list, CEL_PIDS, ids.as_mut_ptr() as u64);

        assert_eq!(handle(owner, 0, CTL_ELEM_LIST, list.as_mut_ptr() as u64), 0);
        assert_eq!(u32_at(&list, CEL_USED), 0);
        assert_eq!(u32_at(&list, CEL_COUNT), 0);
        assert_eq!(ids, [0u8; CTL_ELEM_ID_SIZE * 2]);

        let mut info = [0u8; CTL_ELEM_INFO_SIZE];
        put_id(&mut info, 1);
        assert_eq!(
            handle(owner, 0, CTL_ELEM_INFO, info.as_mut_ptr() as u64),
            -(Errno::Enoent.as_i32() as i64)
        );

        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
    }

    #[test]
    fn missing_mixer_controls_reject_reads_writes_and_oss_mixer() {
        let owner = 0x5101;
        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
        assert!(crate::reserve_card(owner));
        assert!(crate::ops::register(owner, &TEST_OPS));

        let mut value = [0u8; CTL_ELEM_VALUE_SIZE];
        put_id(&mut value, 1);
        assert_eq!(
            handle(owner, 0, CTL_ELEM_READ, value.as_mut_ptr() as u64),
            -(Errno::Enoent.as_i32() as i64)
        );
        assert_eq!(
            handle(owner, 0, CTL_ELEM_WRITE, value.as_mut_ptr() as u64),
            -(Errno::Enoent.as_i32() as i64)
        );

        assert_eq!(mixer_level(owner), None);
        assert!(!set_mixer_level(owner, 80 | (90 << 8)));

        let read_req = (2u64 << 30) | (4u64 << 16) | ((b'M' as u64) << 8);
        let write_req = (1u64 << 30) | (4u64 << 16) | ((b'M' as u64) << 8);
        let mut packed = 10u32 | (20u32 << 8);
        assert_eq!(
            crate::oss::handle(owner, true, read_req, (&mut packed as *mut u32) as u64),
            -(Errno::Enodev.as_i32() as i64)
        );
        packed = 10 | (20 << 8);
        assert_eq!(
            crate::oss::handle(owner, true, write_req, (&mut packed as *mut u32) as u64),
            -(Errno::Enodev.as_i32() as i64)
        );

        let _ = crate::ops::clear(owner);
        let _ = crate::cancel_card_reservation(owner);
    }
}
