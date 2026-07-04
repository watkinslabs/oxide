use super::*;
use crate::oss::oss_params::{AFMT_S16_LE, AFMT_U8, V_S16};
use crate::oss::oss_state::OSS;
use core::sync::atomic::{AtomicU32, Ordering};
use syscall::errno::Errno;

fn cfg(_owner: u32) -> Option<(u32, u32, u32, u32)> { Some((0, 0, 0, 0)) }
fn caps(_owner: u32) -> crate::ops::Caps { Some((1 << V_S16, 1 << 6, 1, 2)) }
fn period(_owner: u32) -> usize { 2048 }
fn hw_params(_owner: u32, _rate: u8, _format: u8, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool { true }
fn hw_params_record(_owner: u32, _rate: u8, _format: u8, _channels: u8, period_bytes: u32, buffer_bytes: u32) -> bool {
    LAST_PERIOD.store(period_bytes, Ordering::SeqCst);
    LAST_BUFFER.store(buffer_bytes, Ordering::SeqCst);
    true
}
fn yes(_owner: u32) -> bool { true }
fn start_only(_owner: u32, start: bool) -> bool { start }
fn submit(_owner: u32, b: &[u8]) -> usize { b.len() }
fn recv(_owner: u32, b: &mut [u8]) -> usize { b.len() }

static LAST_PERIOD: AtomicU32 = AtomicU32::new(0);
static LAST_BUFFER: AtomicU32 = AtomicU32::new(0);

static STOP_FAIL_OPS: crate::ops::SoundOps = crate::ops::SoundOps {
    config: cfg, pcm_caps: caps, cap_caps: caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: start_only, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: start_only, cap_hw_free: yes, pcm_recv: recv,
};

static GEOM_OPS: crate::ops::SoundOps = crate::ops::SoundOps {
    config: cfg, pcm_caps: caps, cap_caps: caps, period_bytes: period,
    pcm_hw_params: hw_params_record, pcm_prepare: yes, pcm_trigger: start_only, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params_record, cap_prepare: yes, cap_trigger: start_only, cap_hw_free: yes, pcm_recv: recv,
};

fn test_err(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[test]
fn parameter_change_does_not_clear_running_state_when_reset_fails() {
    let owner = 0x7100;
    unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);

    assert!(crate::reserve_card(owner));
    assert!(crate::ops::register(owner, &STOP_FAIL_OPS));
    register_card(owner);

    let getfmts_req = (2u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 11;
    let mut fmts = 0u32;
    assert_eq!(handle(owner, false, getfmts_req, (&mut fmts as *mut u32) as u64), 0);
    assert_eq!(fmts, AFMT_S16_LE);

    let bytes = [0x55u8; 128];
    assert_eq!(write(owner, &bytes), bytes.len());
    {
        let guard = OSS.lock();
        let o = guard.iter().find(|o| o.owner == owner).expect("registered OSS state");
        assert!(o.running);
        assert_eq!(o.rate, 6);
    }

    let setfmt_req = (1u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 5;
    let mut fmt = AFMT_U8;
    assert_eq!(handle(owner, false, setfmt_req, (&mut fmt as *mut u32) as u64), test_err(Errno::Einval));
    {
        let guard = OSS.lock();
        let o = guard.iter().find(|o| o.owner == owner).expect("registered OSS state");
        assert!(o.running);
        assert_eq!(o.format, V_S16);
    }

    let speed_req = (1u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 2;
    let mut hz = 48_000u32;
    assert_eq!(handle(owner, false, speed_req, (&mut hz as *mut u32) as u64), test_err(Errno::Eio));
    {
        let guard = OSS.lock();
        let o = guard.iter().find(|o| o.owner == owner).expect("registered OSS state");
        assert!(o.running);
        assert_eq!(o.rate, 6);
    }

    unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);
}

#[test]
fn fragment_ioctl_sets_backend_period_and_space_geometry() {
    let owner = 0x7101;
    unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);
    LAST_PERIOD.store(0, Ordering::SeqCst);
    LAST_BUFFER.store(0, Ordering::SeqCst);

    assert!(crate::reserve_card(owner));
    assert!(crate::ops::register(owner, &GEOM_OPS));
    register_card(owner);

    let setfragment_req = (1u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 14;
    let getblksize_req = (2u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 4;
    let getospace_req = (2u64 << 30) | (16u64 << 16) | ((b'P' as u64) << 8) | 12;
    let subdivide_req = (3u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 10;

    let mut fragment = (4u32 << 16) | 10;
    assert_eq!(handle(owner, false, setfragment_req, (&mut fragment as *mut u32) as u64), 0);

    let mut block = 0u32;
    assert_eq!(handle(owner, false, getblksize_req, (&mut block as *mut u32) as u64), 0);
    assert_eq!(block, 1024);

    let mut space = [0u32; 4];
    assert_eq!(handle(owner, false, getospace_req, space.as_mut_ptr() as u64), 0);
    assert_eq!(space, [4, 4, 1024, 4096]);

    let bytes = [0x33u8; 16];
    assert_eq!(write(owner, &bytes), bytes.len());
    assert_eq!(LAST_PERIOD.load(Ordering::SeqCst), 1024);
    assert_eq!(LAST_BUFFER.load(Ordering::SeqCst), 4096);

    let mut subdivide = 2u32;
    assert_eq!(handle(owner, false, subdivide_req, (&mut subdivide as *mut u32) as u64), test_err(Errno::Einval));

    unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);
}

#[test]
fn subdivide_ioctl_updates_fragment_size_once() {
    let owner = 0x7102;
    unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);
    LAST_PERIOD.store(0, Ordering::SeqCst);
    LAST_BUFFER.store(0, Ordering::SeqCst);

    assert!(crate::reserve_card(owner));
    assert!(crate::ops::register(owner, &GEOM_OPS));
    register_card(owner);

    let subdivide_req = (3u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 10;
    let getblksize_req = (2u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 4;

    let mut subdivide = 0u32;
    assert_eq!(handle(owner, false, subdivide_req, (&mut subdivide as *mut u32) as u64), 0);
    assert_eq!(subdivide, 1);

    subdivide = 4;
    assert_eq!(handle(owner, false, subdivide_req, (&mut subdivide as *mut u32) as u64), 0);
    assert_eq!(subdivide, 4);

    let mut block = 0u32;
    assert_eq!(handle(owner, false, getblksize_req, (&mut block as *mut u32) as u64), 0);
    assert_eq!(block, 512);

    let bytes = [0x44u8; 16];
    assert_eq!(write(owner, &bytes), bytes.len());
    assert_eq!(LAST_PERIOD.load(Ordering::SeqCst), 512);
    assert_eq!(LAST_BUFFER.load(Ordering::SeqCst), 1024);

    subdivide = 2;
    assert_eq!(handle(owner, false, subdivide_req, (&mut subdivide as *mut u32) as u64), test_err(Errno::Einval));

    unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);
}

#[test]
fn missing_ops_do_not_report_fake_fragment_size() {
    let owner = 0x7103;
    unregister_card(owner);
    let _ = crate::ops::clear(owner);
    let _ = crate::cancel_card_reservation(owner);

    assert!(crate::reserve_card(owner));
    register_card(owner);

    let getblksize_req = (2u64 << 30) | (4u64 << 16) | ((b'P' as u64) << 8) | 4;
    let getospace_req = (2u64 << 30) | (16u64 << 16) | ((b'P' as u64) << 8) | 12;
    let mut block = 0u32;
    let mut space = [0u32; 4];

    assert_eq!(handle(owner, false, getblksize_req, (&mut block as *mut u32) as u64), test_err(Errno::Enodev));
    assert_eq!(handle(owner, false, getospace_req, space.as_mut_ptr() as u64), test_err(Errno::Enodev));

    unregister_card(owner);
    let _ = crate::cancel_card_reservation(owner);
}
