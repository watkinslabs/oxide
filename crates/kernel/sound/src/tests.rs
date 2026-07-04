use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as SoundLockClass};

use crate::{cancel_card_reservation, card_number, owner, register_card, reserve_card, unregister_card};
use crate::{capture, ops, oss, pcm, uapi};

const CARD0_NODE_COUNT: usize = 9;
const CARD1_NODE_COUNT: usize = 6;

static TEST_LOCK: AtomicU32 = AtomicU32::new(0);
static ADDED: Spinlock<Vec<(String, Option<(u32, u32)>, bool)>, SoundLockClass> = Spinlock::new(Vec::new());
static REMOVED: Spinlock<Vec<String>, SoundLockClass> = Spinlock::new(Vec::new());

struct TestGuard;

impl Drop for TestGuard {
    fn drop(&mut self) {
        TEST_LOCK.store(0, Ordering::Release);
    }
}

fn test_guard() -> TestGuard {
    while TEST_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
        core::hint::spin_loop();
    }
    TestGuard
}

fn cfg(_owner: u32) -> Option<(u32, u32, u32, u32)> { Some((0, 0, 0, 0)) }
fn caps(_owner: u32) -> ops::Caps { Some((0, 0, 1, 2)) }
fn no_caps(_owner: u32) -> ops::Caps { None }
fn period(_owner: u32) -> usize { 2048 }
fn hw_params(_owner: u32, _rate: u8, _format: u8, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool { true }
fn yes(_owner: u32) -> bool { true }
fn no(_owner: u32) -> bool { false }
fn trigger(_owner: u32, _start: bool) -> bool { true }
fn fail_trigger(_owner: u32, _start: bool) -> bool { false }
fn submit(_owner: u32, b: &[u8]) -> usize { b.len() }
fn recv(_owner: u32, b: &mut [u8]) -> usize { b.len() }

static TEST_OPS: ops::SoundOps = ops::SoundOps {
    config: cfg, pcm_caps: caps, cap_caps: caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_hw_free: yes, pcm_recv: recv,
};

static PLAYBACK_ONLY_OPS: ops::SoundOps = ops::SoundOps {
    config: cfg, pcm_caps: caps, cap_caps: no_caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_hw_free: yes, pcm_recv: recv,
};

static CAPTURE_ONLY_OPS: ops::SoundOps = ops::SoundOps {
    config: cfg, pcm_caps: no_caps, cap_caps: caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_hw_free: yes, pcm_recv: recv,
};

static NO_PCM_OPS: ops::SoundOps = ops::SoundOps {
    config: cfg, pcm_caps: no_caps, cap_caps: no_caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: trigger, pcm_hw_free: yes, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: trigger, cap_hw_free: yes, pcm_recv: recv,
};

static FAIL_STOP_FREE_OPS: ops::SoundOps = ops::SoundOps {
    config: cfg, pcm_caps: caps, cap_caps: caps, period_bytes: period,
    pcm_hw_params: hw_params, pcm_prepare: yes, pcm_trigger: fail_trigger, pcm_hw_free: no, pcm_submit: submit,
    cap_hw_params: hw_params, cap_prepare: yes, cap_trigger: fail_trigger, cap_hw_free: no, pcm_recv: recv,
};

fn add_hook(class: &str, name: &str, dt: Option<(u32, u32)>, factory: Option<drv::NodeFactory>) {
    if class == "sound" {
        ADDED.lock().push((String::from(name), dt, factory.is_some()));
    }
}

fn del_hook(name: &str) {
    REMOVED.lock().push(String::from(name));
}

fn has_node(nodes: &[(String, Option<(u32, u32)>, bool)], name: &str, dev_t: (u32, u32)) -> bool {
    nodes.iter().any(|node| node == &(String::from(name), Some(dev_t), true))
}

fn has_name(nodes: &[(String, Option<(u32, u32)>, bool)], name: &str) -> bool {
    nodes.iter().any(|node| node.0 == name)
}

fn test_err(e: syscall::errno::Errno) -> i64 { -(e.as_i32() as i64) }
fn put_u32(buf: &mut [u8], off: usize, value: u32) { buf[off..off + 4].copy_from_slice(&value.to_le_bytes()); }
fn put_u64(buf: &mut [u8], off: usize, value: u64) { buf[off..off + 8].copy_from_slice(&value.to_le_bytes()); }
fn get_u64(buf: &[u8], off: usize) -> u64 { u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) }

#[test]
fn card_nodes_are_model_owned_and_removed() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(0x10);
    let _ = ops::clear(0x10);

    assert!(reserve_card(0x10));
    assert!(ops::register(0x10, &TEST_OPS));
    assert!(register_card(0x10));
    assert_eq!(owner(), Some(0x10));
    assert_eq!(card_number(0x10), Some(0));
    assert!(register_card(0x10));

    let added = ADDED.lock().clone();
    assert_eq!(added.len(), CARD0_NODE_COUNT);
    assert!(has_node(&added, "snd/controlC0", (116, 0)));
    assert!(has_node(&added, "snd/pcmC0D0p", (116, 16)));
    assert!(has_node(&added, "snd/pcmC0D0c", (116, 24)));
    assert!(drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "controlC0" && d.devname.as_deref() == Some("snd/controlC0")));
    assert!(drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "pcmC0D0p" && d.devname.as_deref() == Some("snd/pcmC0D0p")));
    assert!(has_node(&added, "dsp", (14, 3)));
    assert!(has_node(&added, "dsp0", (14, 3)));
    assert!(has_node(&added, "audio", (14, 4)));
    assert!(has_node(&added, "audio0", (14, 4)));
    assert!(has_node(&added, "mixer", (14, 0)));
    assert!(has_node(&added, "mixer0", (14, 0)));

    assert!(!unregister_card(0x20));
    assert_eq!(REMOVED.lock().len(), 0);
    assert_eq!(owner(), Some(0x10));

    assert!(unregister_card(0x10));
    let removed = REMOVED.lock().clone();
    assert_eq!(removed.len(), CARD0_NODE_COUNT);
    assert!(removed.iter().any(|n| n == "snd/controlC0"));
    assert!(removed.iter().any(|n| n == "snd/pcmC0D0p"));
    assert!(removed.iter().any(|n| n == "snd/pcmC0D0c"));
    assert!(removed.iter().any(|n| n == "dsp"));
    assert!(removed.iter().any(|n| n == "dsp0"));
    assert!(removed.iter().any(|n| n == "audio"));
    assert!(removed.iter().any(|n| n == "audio0"));
    assert!(removed.iter().any(|n| n == "mixer"));
    assert!(removed.iter().any(|n| n == "mixer0"));

    assert!(!unregister_card(0x10));
    assert_eq!(REMOVED.lock().len(), CARD0_NODE_COUNT);
    assert_eq!(owner(), None);
    assert!(ops::ops_for(0x10).is_none());
    let _ = ops::clear(0x10);
}

#[test]
fn card_nodes_follow_reported_stream_directions() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);

    for (owner_id, ops_table, expect_playback, expect_capture, expect_count) in [
        (0x41, &PLAYBACK_ONLY_OPS, true, false, 8usize),
        (0x42, &CAPTURE_ONLY_OPS, false, true, 8usize),
        (0x43, &NO_PCM_OPS, false, false, 3usize),
    ] {
        ADDED.lock().clear();
        REMOVED.lock().clear();
        let _ = unregister_card(owner_id);
        let _ = ops::clear(owner_id);

        assert!(reserve_card(owner_id));
        assert!(ops::register(owner_id, ops_table));
        assert!(register_card(owner_id));
        let added = ADDED.lock().clone();
        assert_eq!(added.len(), expect_count);
        assert!(has_node(&added, "snd/controlC0", (116, 0)));
        assert_eq!(has_name(&added, "snd/pcmC0D0p"), expect_playback);
        assert_eq!(has_name(&added, "snd/pcmC0D0c"), expect_capture);
        assert_eq!(has_name(&added, "dsp"), expect_playback || expect_capture);
        assert_eq!(has_name(&added, "audio"), expect_playback || expect_capture);
        assert!(has_node(&added, "mixer", (14, 0)));
        assert_eq!(pcm::has_card(owner_id), expect_playback);
        assert_eq!(capture::has_card(owner_id), expect_capture);
        assert_eq!(oss::has_card(owner_id), expect_playback || expect_capture);

        assert!(unregister_card(owner_id));
        let _ = ops::clear(owner_id);
    }
}

#[test]
fn pcm_control_ops_propagate_backend_failures() {
    let _guard = test_guard();
    let owner_id = 0x44;
    let _ = pcm::unregister_card(owner_id);
    let _ = capture::unregister_card(owner_id);
    let _ = cancel_card_reservation(owner_id);
    let _ = ops::clear(owner_id);

    assert!(reserve_card(owner_id));
    assert!(ops::register(owner_id, &FAIL_STOP_FREE_OPS));
    pcm::register_card(owner_id);
    capture::register_card(owner_id);

    assert_eq!(pcm::handle(owner_id, uapi::PCM_HW_FREE, 0), test_err(syscall::errno::Errno::Eio));
    assert_eq!(pcm::handle(owner_id, uapi::PCM_DROP, 0), test_err(syscall::errno::Errno::Eio));
    assert_eq!(capture::handle(owner_id, uapi::PCM_HW_FREE, 0), test_err(syscall::errno::Errno::Eio));
    assert_eq!(capture::handle(owner_id, uapi::PCM_DROP, 0), test_err(syscall::errno::Errno::Eio));

    let _ = pcm::unregister_card(owner_id);
    let _ = capture::unregister_card(owner_id);
    let _ = ops::clear(owner_id);
    let _ = cancel_card_reservation(owner_id);
}

#[test]
fn pcm_sync_ptr_does_not_fabricate_hardware_progress() {
    let _guard = test_guard();
    let owner_id = 0x45;
    let _ = pcm::unregister_card(owner_id);
    let _ = capture::unregister_card(owner_id);
    let _ = cancel_card_reservation(owner_id);
    let _ = ops::clear(owner_id);

    assert!(reserve_card(owner_id));
    assert!(ops::register(owner_id, &TEST_OPS));
    pcm::register_card(owner_id);
    capture::register_card(owner_id);

    let mut sync = [0u8; uapi::SYNC_PTR_SIZE];
    put_u32(&mut sync, uapi::SP_FLAGS, 0);
    put_u64(&mut sync, uapi::SP_CONTROL_APPL_PTR, 77);
    assert_eq!(pcm::handle(owner_id, uapi::PCM_SYNC_PTR, sync.as_mut_ptr() as u64), 0);
    assert_eq!(get_u64(&sync, uapi::SP_CONTROL_APPL_PTR), 77);
    assert_eq!(get_u64(&sync, uapi::SP_STATUS_HW_PTR), 0);

    sync.fill(0);
    put_u32(&mut sync, uapi::SP_FLAGS, 0);
    put_u64(&mut sync, uapi::SP_CONTROL_APPL_PTR, 33);
    assert_eq!(capture::handle(owner_id, uapi::PCM_SYNC_PTR, sync.as_mut_ptr() as u64), 0);
    assert_eq!(get_u64(&sync, uapi::SP_CONTROL_APPL_PTR), 33);
    assert_eq!(get_u64(&sync, uapi::SP_STATUS_HW_PTR), 0);

    assert_eq!(pcm::handle(owner_id, uapi::PCM_PAUSE, 0), test_err(syscall::errno::Errno::Enotty));
    assert_eq!(pcm::handle(owner_id, uapi::PCM_TSTAMP, 0), test_err(syscall::errno::Errno::Enotty));
    assert_eq!(pcm::handle(owner_id, uapi::PCM_TTSTAMP, 0), test_err(syscall::errno::Errno::Enotty));
    assert_eq!(capture::handle(owner_id, uapi::PCM_TSTAMP, 0), test_err(syscall::errno::Errno::Enotty));
    assert_eq!(capture::handle(owner_id, uapi::PCM_TTSTAMP, 0), test_err(syscall::errno::Errno::Enotty));

    let _ = pcm::unregister_card(owner_id);
    let _ = capture::unregister_card(owner_id);
    let _ = ops::clear(owner_id);
    let _ = cancel_card_reservation(owner_id);
}

#[test]
fn card_reservation_allocates_per_owner_cards_before_publication() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(0x10);
    let _ = unregister_card(0x20);
    let _ = ops::clear(0x10);
    let _ = ops::clear(0x20);

    assert!(reserve_card(0x10));
    assert_eq!(owner(), Some(0x10));
    assert_eq!(card_number(0x10), Some(0));
    assert!(reserve_card(0x10));
    assert!(reserve_card(0x20));
    assert_eq!(card_number(0x20), Some(1));
    assert_eq!(ADDED.lock().len(), 0);

    assert!(ops::register(0x10, &TEST_OPS));
    assert!(ops::register(0x20, &TEST_OPS));
    assert!(register_card(0x10));
    assert!(register_card(0x20));

    let added = ADDED.lock().clone();
    assert_eq!(added.len(), CARD0_NODE_COUNT + CARD1_NODE_COUNT);
    assert!(has_node(&added, "snd/controlC0", (116, 0)));
    assert!(has_node(&added, "snd/pcmC0D0p", (116, 16)));
    assert!(has_node(&added, "snd/pcmC0D0c", (116, 24)));
    assert!(has_node(&added, "snd/controlC1", (116, 32)));
    assert!(has_node(&added, "snd/pcmC1D0p", (116, 48)));
    assert!(has_node(&added, "snd/pcmC1D0c", (116, 56)));
    assert!(has_node(&added, "dsp1", (14, 19)));
    assert!(has_node(&added, "audio1", (14, 20)));
    assert!(has_node(&added, "mixer1", (14, 16)));

    assert!(unregister_card(0x10));
    assert_eq!(owner(), Some(0x20));
    assert_eq!(card_number(0x20), Some(1));
    assert!(ops::ops_for(0x10).is_none());
    assert!(ops::ops_for(0x20).is_some());
    assert!(unregister_card(0x20));
    assert_eq!(owner(), None);
    assert!(ops::ops_for(0x10).is_none());
    assert!(ops::ops_for(0x20).is_none());
}

#[test]
fn cancel_card_reservation_only_releases_unpublished_cards() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(0x10);
    let _ = unregister_card(0x20);
    let _ = ops::clear(0x10);
    let _ = ops::clear(0x20);

    assert!(reserve_card(0x10));
    assert!(cancel_card_reservation(0x10));
    assert_eq!(card_number(0x10), None);
    assert!(!cancel_card_reservation(0x10));
    assert_eq!(ADDED.lock().len(), 0);
    assert_eq!(REMOVED.lock().len(), 0);

    assert!(reserve_card(0x20));
    assert!(ops::register(0x20, &TEST_OPS));
    assert!(register_card(0x20));
    assert!(!cancel_card_reservation(0x20));
    assert_eq!(card_number(0x20), Some(0));
    assert!(unregister_card(0x20));
    assert!(ops::ops_for(0x20).is_none());
    let _ = ops::clear(0x20);
}

#[test]
fn card_publication_conflict_rolls_back_partial_nodes_and_owner_state() {
    let _guard = test_guard();
    drv::set_devtmpfs_hook(add_hook);
    drv::set_devtmpfs_del_hook(del_hook);
    ADDED.lock().clear();
    REMOVED.lock().clear();
    let _ = unregister_card(0x10);
    let _ = unregister_card(0x20);
    let _ = unregister_card(0x30);
    let _ = ops::clear(0x10);
    let _ = ops::clear(0x20);
    let _ = ops::clear(0x30);

    let conflict = drv::try_device_add(Arc::new(
        drv::Device::new("sound", String::from("pcmC0D0p"), 0, 0, crate::device::MINOR_PCM_P as u32)
            .with_devnode("sound", String::from("snd/pcmC0D0p"), Some((116, 16)))))
        .expect("conflict device registration");
    ADDED.lock().clear();
    REMOVED.lock().clear();

    assert!(reserve_card(0x30));
    assert!(ops::register(0x30, &TEST_OPS));
    assert!(!register_card(0x30));

    let added = ADDED.lock().clone();
    assert_eq!(added.len(), 1);
    assert!(has_node(&added, "snd/controlC0", (116, 0)));
    let removed = REMOVED.lock().clone();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0], String::from("snd/controlC0"));
    assert!(!drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "controlC0"));
    assert!(drv::devices().iter().any(|d| d.bus == "sound" && d.addr == "pcmC0D0p"));
    assert_eq!(owner(), None);
    assert_eq!(card_number(0x30), None);
    assert!(ops::ops_for(0x30).is_none());
    assert!(!pcm::has_card(0x30));
    assert!(!capture::has_card(0x30));
    assert!(!oss::has_card(0x30));

    drv::device_del(&conflict);
    let _ = ops::clear(0x30);
}

#[test]
fn substream_runtime_state_is_owner_keyed() {
    let _guard = test_guard();

    pcm::unregister_card(0x10);
    pcm::unregister_card(0x20);
    capture::unregister_card(0x10);
    capture::unregister_card(0x20);
    oss::unregister_card(0x10);
    oss::unregister_card(0x20);

    pcm::register_card(0x10);
    pcm::register_card(0x20);
    pcm::register_card(0x10);
    capture::register_card(0x10);
    capture::register_card(0x20);
    capture::register_card(0x10);
    oss::register_card(0x10);
    oss::register_card(0x20);
    oss::register_card(0x10);

    assert_eq!(pcm::registered_count(), 2);
    assert!(pcm::has_card(0x10));
    assert!(pcm::has_card(0x20));
    assert_eq!(capture::registered_count(), 2);
    assert!(capture::has_card(0x10));
    assert!(capture::has_card(0x20));
    assert_eq!(oss::registered_count(), 2);
    assert!(oss::has_card(0x10));
    assert!(oss::has_card(0x20));

    pcm::unregister_card(0x10);
    capture::unregister_card(0x10);
    oss::unregister_card(0x10);

    assert_eq!(pcm::registered_count(), 1);
    assert!(!pcm::has_card(0x10));
    assert!(pcm::has_card(0x20));
    assert_eq!(capture::registered_count(), 1);
    assert!(!capture::has_card(0x10));
    assert!(capture::has_card(0x20));
    assert_eq!(oss::registered_count(), 1);
    assert!(!oss::has_card(0x10));
    assert!(oss::has_card(0x20));

    pcm::unregister_card(0x20);
    capture::unregister_card(0x20);
    oss::unregister_card(0x20);
}
