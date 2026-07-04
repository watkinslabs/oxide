// `sound` — the ALSA core (snd_pcm_lib + control + the char-device ABI) for
// virtio-snd cards. The PRIMARY surface is ALSA `/dev/snd/*`
// (controlC<N> + pcmC<N>D0p, served by the SNDRV_*_IOCTL ABI); the OSS
// `/dev/dsp`/`/dev/mixer` nodes are snd-pcm-oss emulation over the SAME
// drv-virtio-snd substream ops — the modern-Linux layering (docs/58§5–6).
// virtio-snd is the card driver (snd_pcm_ops); this crate owns the
// substream state machine + hw_params refinement + ring accounting.

#![no_std]
extern crate alloc;

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as SoundLockClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError, InodeBuilder, FileOps, default_inode_ops, mk_mode};

mod uapi;
pub mod ops;
mod pcm;
mod capture;
mod control;
mod oss;

use uapi::{PCM_MAGIC, CTL_MAGIC};

/// High-32 tag ('Snd\0') + card/minor in the low bits — routes the shared
/// ioctl dispatcher to sound nodes while `i_private` carries the owner key.
const SND_INO_BASE: Ino = 0x536E_6400_0000_0000;
const SND_INO_MASK: Ino = 0xFFFF_FFFF_0000_0000;
const MINOR_CONTROL: u64 = 0x00; // controlC0
const MINOR_PCM_P:   u64 = 0x10; // pcmC0D0p (playback)
const MINOR_PCM_C:   u64 = 0x11; // pcmC0D0c (capture)
const MINOR_DSP:     u64 = 0x20; // /dev/dsp
const MINOR_AUDIO:   u64 = 0x21; // /dev/audio
const MINOR_MIXER:   u64 = 0x22; // /dev/mixer

const NO_CARD_OWNER: u32 = u32::MAX;

struct SoundCard {
    owner: u32,
    card: u32,
    nodes: Vec<Arc<drv::Device>>,
}

static CARDS: Spinlock<Vec<SoundCard>, SoundLockClass> = Spinlock::new(Vec::new());

/// Backend-private state (`i_private`) for a sound node: the owning card key
/// plus the device minor that routes `controlC0`/`pcmC0D0p`/… dispatch.
/// # C: O(1)
struct SndData {
    owner: u32,
    card: u32,
    minor: u64,
}

/// `file_operations` for every `/dev/snd/*` + OSS node — `read`/`write`
/// dispatch on the node's stored minor (the same key the ioctl path uses),
/// preserving the per-node data path:
///   - `pcmC0D0p`  : read → 0, write → PCM byte transfer (`Eio` on a 0 transfer)
///   - `pcmC0D0c`  : read → capture transfer, write → `Eio`
///   - `controlC0` : read → 0, write → `Eio`
///   - `/dev/dsp`,`/dev/audio` : read/write → OSS transfer (`Eio` on 0 write)
///   - `/dev/mixer`: read → 0, write → accept (`Ok(len)`)
struct SndFileOps;
impl FileOps for SndFileOps {
    fn read(&self, inode: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> {
        let data = match inode.private::<SndData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        if b.is_empty() { return Ok(0); }
        match data.minor {
            // OSS /dev/dsp read(2) → capture (snd-pcm-oss over the same RXQ).
            MINOR_DSP | MINOR_AUDIO => Ok(oss::read(data.owner, b)),
            MINOR_PCM_C             => Ok(capture::read_bytes(data.owner, b)),
            // pcmC0D0p / controlC0 / mixer → no readable byte stream.
            _ => Ok(0),
        }
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let data = match inode.private::<SndData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        match data.minor {
            MINOR_PCM_P => {
                if b.is_empty() { return Ok(0); }
                let n = pcm::write_bytes(data.owner, b);
                if n == 0 { Err(VfsError::Eio) } else { Ok(n) }
            }
            MINOR_DSP | MINOR_AUDIO => {
                if b.is_empty() { return Ok(0); }
                let n = oss::write(data.owner, b);
                if n == 0 { Err(VfsError::Eio) } else { Ok(n) }
            }
            MINOR_MIXER => Ok(b.len()),
            // pcmC0D0c / controlC0 → not writable.
            _ => Err(VfsError::Eio),
        }
    }
}

/// Build a `/dev/snd/*` (or OSS) char-device inode for `minor`: `S_IFCHR|0o666`,
/// `ino = SND_INO_BASE | minor` (the routing tag the ioctl path reads), the
/// shared `SndFileOps` data path, lookup → `ENOTDIR` (default i_op). # C: O(1)
fn make_snd_inode(owner: u32, card: u32, minor: u64) -> InodeRef {
    InodeBuilder::new(SND_INO_BASE | ((card as Ino) << 8) | minor, mk_mode(FileType::CharDev, 0o666),
                      default_inode_ops(), Arc::new(SndFileOps))
        .private(Arc::new(SndData { owner, card, minor }))
        .build()
}

struct SoundNodeTemplate {
    class: &'static str,
    minor: u64,
}

const OSS_NODES: &[SoundNodeTemplate] = &[
    SoundNodeTemplate { class: "sound", minor: MINOR_DSP },
    SoundNodeTemplate { class: "sound", minor: MINOR_AUDIO },
    SoundNodeTemplate { class: "sound", minor: MINOR_MIXER },
];

fn alsa_node_name(card: u32, minor: u64) -> String {
    match minor {
        MINOR_CONTROL => alloc::format!("snd/controlC{}", card),
        MINOR_PCM_P => alloc::format!("snd/pcmC{}D0p", card),
        MINOR_PCM_C => alloc::format!("snd/pcmC{}D0c", card),
        _ => alloc::format!("snd/unknownC{}M{}", card, minor),
    }
}

fn alsa_dev_t(card: u32, minor: u64) -> (u32, u32) {
    let base = card.checked_mul(32).expect("sound card minor overflow");
    match minor {
        MINOR_CONTROL => (116, base),
        MINOR_PCM_P => (116, base + 16),
        MINOR_PCM_C => (116, base + 24),
        _ => (116, base + minor as u32),
    }
}

fn oss_node_name(card: u32, minor: u64) -> String {
    match minor {
        MINOR_DSP => alloc::format!("dsp{}", card),
        MINOR_AUDIO => alloc::format!("audio{}", card),
        MINOR_MIXER => alloc::format!("mixer{}", card),
        _ => alloc::format!("sound{}", minor),
    }
}

fn oss_dev_t(card: u32, minor: u64) -> (u32, u32) {
    let base = card.checked_mul(16).expect("OSS minor overflow");
    match minor {
        MINOR_DSP => (14, base + 3),
        MINOR_AUDIO => (14, base + 4),
        MINOR_MIXER => (14, base),
        _ => (14, base + minor as u32),
    }
}

fn sound_addr(dev_name: &str) -> String {
    match dev_name.rsplit('/').next() {
        Some(leaf) => String::from(leaf),
        None => String::from(dev_name),
    }
}

fn add_sound_node(owner: u32, card: u32, class: &'static str, dev_name: String, dev_t: (u32, u32), minor: u64) -> Option<Arc<drv::Device>> {
    let factory: drv::NodeFactory = Arc::new(move || make_snd_inode(owner, card, minor));
    let addr = sound_addr(&dev_name);
    drv::try_device_add(Arc::new(
        drv::Device::new(class, addr, 0, 0, minor as u32)
            .with_devnode(class, dev_name, Some(dev_t))
            .with_node_factory(factory),
    )).ok()
}

fn push_sound_node(
    published: &mut Vec<Arc<drv::Device>>,
    owner: u32,
    card: u32,
    class: &'static str,
    dev_name: String,
    dev_t: (u32, u32),
    minor: u64,
) -> bool {
    match add_sound_node(owner, card, class, dev_name, dev_t, minor) {
        Some(dev) => {
            published.push(dev);
            true
        }
        None => false,
    }
}

fn rollback_published_nodes(published: &[Arc<drv::Device>]) {
    for node in published.iter().rev() {
        drv::device_del(node);
    }
}

fn publish_card_nodes(owner: u32, card: u32, has_playback: bool, has_capture: bool) -> Option<Vec<Arc<drv::Device>>> {
    let mut published = Vec::new();
    let control_name = alsa_node_name(card, MINOR_CONTROL);
    if !push_sound_node(&mut published, owner, card, "sound", control_name, alsa_dev_t(card, MINOR_CONTROL), MINOR_CONTROL) {
        rollback_published_nodes(&published);
        return None;
    }
    if has_playback {
        let dev_name = alsa_node_name(card, MINOR_PCM_P);
        if !push_sound_node(&mut published, owner, card, "sound", dev_name, alsa_dev_t(card, MINOR_PCM_P), MINOR_PCM_P) {
            rollback_published_nodes(&published);
            return None;
        }
    }
    if has_capture {
        let dev_name = alsa_node_name(card, MINOR_PCM_C);
        if !push_sound_node(&mut published, owner, card, "sound", dev_name, alsa_dev_t(card, MINOR_PCM_C), MINOR_PCM_C) {
            rollback_published_nodes(&published);
            return None;
        }
    }
    for node in OSS_NODES {
        if matches!(node.minor, MINOR_DSP | MINOR_AUDIO) && !has_playback && !has_capture {
            continue;
        }
        let dev_name = oss_node_name(card, node.minor);
        if !push_sound_node(&mut published, owner, card, node.class, dev_name, oss_dev_t(card, node.minor), node.minor) {
            rollback_published_nodes(&published);
            return None;
        }
    }
    if card == 0 {
        let mut ok = true;
        if has_playback || has_capture {
            ok = push_sound_node(&mut published, owner, card, "sound", String::from("dsp"), (14, 3), MINOR_DSP)
                && push_sound_node(&mut published, owner, card, "sound", String::from("audio"), (14, 4), MINOR_AUDIO);
        }
        ok = ok && push_sound_node(&mut published, owner, card, "sound", String::from("mixer"), (14, 0), MINOR_MIXER);
        if !ok {
            rollback_published_nodes(&published);
            return None;
        }
    }
    Some(published)
}

/// Sound-node ioctl entry point for the shared `sys_ioctl` dispatch chain.
/// Routes by the node minor + ioctl magic. Returns `Some(rv)` for sound
/// nodes, `None` otherwise. # C: O(1) excluding a blocking PCM transfer
pub fn handle_ioctl(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    let ino = inode.ino();
    if ino & SND_INO_MASK != SND_INO_BASE { return None; }
    let data = match inode.private::<SndData>() {
        Some(data) => data,
        None => return Some(-(syscall::errno::Errno::Einval.as_i32() as i64)),
    };
    let group = (req >> 8) & 0xFF;
    let nr = req & 0xFF;
    Some(match data.minor {
        MINOR_PCM_P if group == PCM_MAGIC => pcm::handle(data.owner, nr, arg),
        MINOR_PCM_C if group == PCM_MAGIC => capture::handle(data.owner, nr, arg),
        MINOR_CONTROL if group == CTL_MAGIC => control::handle(data.owner, data.card, nr, arg),
        MINOR_DSP | MINOR_AUDIO => oss::handle(data.owner, false, req, arg),
        MINOR_MIXER => oss::handle(data.owner, true, req, arg),
        // Unknown ioctl on a sound node → ENOTTY (don't fall through).
        _ => -(syscall::errno::Errno::Enotty.as_i32() as i64),
    })
}

/// Register the ALSA (primary) + OSS (emulation) nodes for a probed card.
/// Called from the sound card driver's probe after it has installed ops.
/// # C: O(depth)
pub fn register_card(owner: u32) -> bool {
    if ops::ops_for(owner).is_none() {
        return false;
    }
    if !reserve_card(owner) {
        return false;
    }
    let card = match card_number(owner) {
        Some(card) => card,
        None => return false,
    };
    if CARDS.lock().iter().any(|record| record.owner == owner && !record.nodes.is_empty()) {
        return true;
    }
    let has_playback = ops::pcm_caps(owner).is_some();
    let has_capture = ops::cap_caps(owner).is_some();
    if has_playback {
        pcm::register_card(owner);
    }
    if has_capture {
        capture::register_card(owner);
    }
    if has_playback || has_capture {
        oss::register_card(owner);
    }
    devfs::register_dir("/dev/snd");
    let Some(published) = publish_card_nodes(owner, card, has_playback, has_capture) else {
        rollback_card_registration(owner);
        return false;
    };
    let mut published = Some(published);
    {
        let mut cards = CARDS.lock();
        let Some(record) = cards.iter_mut().find(|record| record.owner == owner) else {
            drop(cards);
            if let Some(nodes) = published.take() {
                rollback_published_nodes(&nodes);
            }
            rollback_card_registration(owner);
            return false;
        };
        if record.nodes.is_empty() {
            record.nodes = published.take().unwrap_or_default();
        }
    }
    if let Some(nodes) = published {
        rollback_published_nodes(&nodes);
        rollback_card_registration(owner);
    }
    true
}

fn rollback_card_registration(owner: u32) {
    control::unregister_card(owner);
    oss::unregister_card(owner);
    capture::unregister_card(owner);
    pcm::unregister_card(owner);
    let _ = ops::clear(owner);
    let mut cards = CARDS.lock();
    if let Some(idx) = cards.iter().position(|record| record.owner == owner && record.nodes.is_empty()) {
        cards.remove(idx);
    }
}

/// Reserve a stable ALSA card number before the transport probe allocates or
/// publishes userspace-visible sound state. Same-owner calls are idempotent.
/// # C: O(cards)
pub fn reserve_card(owner: u32) -> bool {
    if owner == NO_CARD_OWNER {
        return false;
    }
    let mut cards = CARDS.lock();
    if cards.iter().any(|record| record.owner == owner) {
        return true;
    }
    let mut card = 0u32;
    while cards.iter().any(|record| record.card == card) {
        card = card.checked_add(1).expect("sound card number overflow");
    }
    cards.push(SoundCard { owner, card, nodes: Vec::new() });
    true
}

/// Cancel a reserved-but-unpublished card number. This is the probe-failure
/// path before ALSA/OSS nodes have been made visible.
/// # C: O(cards)
pub fn cancel_card_reservation(owner: u32) -> bool {
    let mut cards = CARDS.lock();
    let Some(idx) = cards
        .iter()
        .position(|record| record.owner == owner && record.nodes.is_empty())
    else {
        return false;
    };
    cards.remove(idx);
    true
}

/// Stable card number assigned to `owner`.
/// # C: O(cards)
pub fn card_number(owner: u32) -> Option<u32> {
    CARDS.lock()
        .iter()
        .find(|record| record.owner == owner)
        .map(|record| record.card)
}

/// First registered sound-card owner. Kept for diagnostics that still need a
/// default card, not for data-path dispatch.
/// # C: O(1)
pub fn owner() -> Option<u32> {
    CARDS.lock().first().map(|record| record.owner)
}

/// Remove ALSA/OSS nodes for the card being removed.
/// # C: O(nodes * depth)
pub fn unregister_card(owner: u32) -> bool {
    let record = {
        let mut cards = CARDS.lock();
        let Some(idx) = cards.iter().position(|record| record.owner == owner) else {
            return false;
        };
        cards.remove(idx)
    };
    for node in record.nodes.iter().rev() {
        drv::device_del(node);
    }
    control::unregister_card(owner);
    oss::unregister_card(owner);
    capture::unregister_card(owner);
    pcm::unregister_card(owner);
    let _ = ops::clear(owner);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use core::sync::atomic::{AtomicU32, Ordering};

    const CARD0_NODE_COUNT: usize = 9;
    const CARD1_NODE_COUNT: usize = 6;

    static TEST_LOCK: AtomicU32 = AtomicU32::new(0);
    static ADDED: Spinlock<Vec<(String, Option<(u32, u32)>, bool)>, SoundLockClass>
        = Spinlock::new(Vec::new());
    static REMOVED: Spinlock<Vec<String>, SoundLockClass> = Spinlock::new(Vec::new());

    struct TestGuard;

    impl Drop for TestGuard {
        fn drop(&mut self) {
            TEST_LOCK.store(0, Ordering::Release);
        }
    }

    fn test_guard() -> TestGuard {
        while TEST_LOCK
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
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
    fn trigger(_owner: u32, _start: bool) -> bool { true }
    fn submit(_owner: u32, b: &[u8]) -> usize { b.len() }
    fn recv(_owner: u32, b: &mut [u8]) -> usize { b.len() }

    static TEST_OPS: ops::SoundOps = ops::SoundOps {
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

    static PLAYBACK_ONLY_OPS: ops::SoundOps = ops::SoundOps {
        config: cfg,
        pcm_caps: caps,
        cap_caps: no_caps,
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

    static CAPTURE_ONLY_OPS: ops::SoundOps = ops::SoundOps {
        config: cfg,
        pcm_caps: no_caps,
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

    static NO_PCM_OPS: ops::SoundOps = ops::SoundOps {
        config: cfg,
        pcm_caps: no_caps,
        cap_caps: no_caps,
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
        assert!(register_card(0x10), "same-owner register is idempotent");

        let added = ADDED.lock().clone();
        assert_eq!(added.len(), CARD0_NODE_COUNT);
        assert!(has_node(&added, "snd/controlC0", (116, 0)));
        assert!(has_node(&added, "snd/pcmC0D0p", (116, 16)));
        assert!(has_node(&added, "snd/pcmC0D0c", (116, 24)));
        assert!(drv::devices().iter().any(|d| d.bus == "sound"
            && d.addr == "controlC0"
            && d.devname.as_deref() == Some("snd/controlC0")));
        assert!(drv::devices().iter().any(|d| d.bus == "sound"
            && d.addr == "pcmC0D0p"
            && d.devname.as_deref() == Some("snd/pcmC0D0p")));
        assert!(has_node(&added, "dsp", (14, 3)));
        assert!(has_node(&added, "dsp0", (14, 3)));
        assert!(has_node(&added, "audio", (14, 4)));
        assert!(has_node(&added, "audio0", (14, 4)));
        assert!(has_node(&added, "mixer", (14, 0)));
        assert!(has_node(&added, "mixer0", (14, 0)));

        assert!(!unregister_card(0x20), "different owner cannot remove a live card");
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
        assert_eq!(REMOVED.lock().len(), CARD0_NODE_COUNT, "second unregister is idempotent");
        assert_eq!(owner(), None);
        assert!(ops::ops_for(0x10).is_none(), "ops must not be visible after owner release");
        let _ = ops::clear(0x10);
    }

    #[test]
    fn card_nodes_follow_reported_stream_directions() {
        let _guard = test_guard();
        drv::set_devtmpfs_hook(add_hook);
        drv::set_devtmpfs_del_hook(del_hook);

        for (owner, ops_table, expect_playback, expect_capture, expect_count) in [
            (0x41, &PLAYBACK_ONLY_OPS, true, false, 8usize),
            (0x42, &CAPTURE_ONLY_OPS, false, true, 8usize),
            (0x43, &NO_PCM_OPS, false, false, 3usize),
        ] {
            ADDED.lock().clear();
            REMOVED.lock().clear();
            let _ = unregister_card(owner);
            let _ = ops::clear(owner);

            assert!(reserve_card(owner));
            assert!(ops::register(owner, ops_table));
            assert!(register_card(owner));
            let added = ADDED.lock().clone();
            assert_eq!(added.len(), expect_count);
            assert!(has_node(&added, "snd/controlC0", (116, 0)));
            assert_eq!(has_name(&added, "snd/pcmC0D0p"), expect_playback);
            assert_eq!(has_name(&added, "snd/pcmC0D0c"), expect_capture);
            assert_eq!(has_name(&added, "dsp"), expect_playback || expect_capture);
            assert_eq!(has_name(&added, "audio"), expect_playback || expect_capture);
            assert!(has_node(&added, "mixer", (14, 0)));
            assert_eq!(pcm::has_card(owner), expect_playback);
            assert_eq!(capture::has_card(owner), expect_capture);
            assert_eq!(oss::has_card(owner), expect_playback || expect_capture);

            assert!(unregister_card(owner));
            let _ = ops::clear(owner);
        }
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
        assert!(reserve_card(0x10), "same-owner reservation is idempotent");
        assert!(reserve_card(0x20), "second owner gets its own card number");
        assert_eq!(card_number(0x20), Some(1));
        assert_eq!(ADDED.lock().len(), 0, "reservation must not publish nodes");

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
        assert!(ops::ops_for(0x10).is_none(), "removed owner ops are hidden");
        assert!(ops::ops_for(0x20).is_some(), "remaining owner ops stay visible");
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
        assert!(
            !cancel_card_reservation(0x20),
            "published cards must use unregister_card"
        );
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
            drv::Device::new("sound", String::from("pcmC0D0p"), 0, 0, MINOR_PCM_P as u32)
                .with_devnode("sound", String::from("snd/pcmC0D0p"), Some((116, 16)))))
            .expect("conflict device registration");
        ADDED.lock().clear();
        REMOVED.lock().clear();

        assert!(reserve_card(0x30));
        assert!(ops::register(0x30, &TEST_OPS));
        assert!(!register_card(0x30), "conflicting model device fails card publication");

        let added = ADDED.lock().clone();
        assert_eq!(added.len(), 1, "only nodes before the conflict may be published");
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
}
