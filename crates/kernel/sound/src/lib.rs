// `sound` — the ALSA core (snd_pcm_lib + control + the char-device ABI) for
// the virtio-snd card. The PRIMARY surface is ALSA `/dev/snd/*`
// (controlC<N> + pcmC<N>D0p, served by the SNDRV_*_IOCTL ABI); the OSS
// `/dev/dsp`/`/dev/mixer` nodes are snd-pcm-oss emulation over the SAME
// drv-virtio-snd substream ops — the modern-Linux layering (docs/58§5–6).
// virtio-snd is the card driver (snd_pcm_ops); this crate owns the
// substream state machine + hw_params refinement + ring accounting.

#![no_std]
extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as SoundLockClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError, InodeBuilder, FileOps, default_inode_ops, mk_mode};

mod uapi;
pub mod ops;
mod pcm;
mod capture;
mod control;
mod oss;

use uapi::{PCM_MAGIC, CTL_MAGIC};

/// High-32 tag ('Snd\0') + minor in the low byte — routes the shared ioctl
/// dispatcher to the right node.
const SND_INO_BASE: Ino = 0x536E_6400_0000_0000;
const SND_INO_MASK: Ino = 0xFFFF_FFFF_0000_0000;
const MINOR_CONTROL: u64 = 0x00; // controlC<N>
const MINOR_PCM_P:   u64 = 0x10; // pcmC<N>D0p (playback)
const MINOR_PCM_C:   u64 = 0x11; // pcmC<N>D0c (capture)
const MINOR_DSP:     u64 = 0x20; // /dev/dsp
const MINOR_AUDIO:   u64 = 0x21; // /dev/audio
const MINOR_MIXER:   u64 = 0x22; // /dev/mixer

struct CardPublication {
    card_id: u32,
    ops_endpoint: ops::OpsEndpoint,
    nodes: Vec<Arc<drv::Device>>,
}

static CARDS: Spinlock<Vec<CardPublication>, SoundLockClass> = Spinlock::new(Vec::new());
static NEXT_CARD_ID: AtomicU32 = AtomicU32::new(0);

/// Backend-private state (`i_private`) for a sound node: the device minor that
/// keys the shared read/write/ioctl dispatch (`controlC0`/`pcmC0D0p`/…). The
/// old per-inode `ino()` tag is now `SND_INO_BASE | minor` on the inode. # C: O(1)
struct SndData { card_id: u32, minor: u64 }

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
        let (card_id, minor) = match inode.private::<SndData>() {
            Some(d) => (d.card_id, d.minor),
            None => return Err(VfsError::Einval),
        };
        if b.is_empty() { return Ok(0); }
        match minor {
            // OSS /dev/dsp read(2) → capture (snd-pcm-oss over the same RXQ).
            MINOR_DSP | MINOR_AUDIO => Ok(oss::read(card_id, b)),
            MINOR_PCM_C             => Ok(capture::read_bytes(card_id, b)),
            // pcmC0D0p / controlC0 / mixer → no readable byte stream.
            _ => Ok(0),
        }
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let (card_id, minor) = match inode.private::<SndData>() {
            Some(d) => (d.card_id, d.minor),
            None => return Err(VfsError::Einval),
        };
        match minor {
            MINOR_PCM_P => {
                if b.is_empty() { return Ok(0); }
                let n = pcm::write_bytes(card_id, b);
                if n == 0 { Err(VfsError::Eio) } else { Ok(n) }
            }
            MINOR_DSP | MINOR_AUDIO => {
                if b.is_empty() { return Ok(0); }
                let n = oss::write(card_id, b);
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
fn make_snd_inode(card_id: u32, minor: u64) -> InodeRef {
    InodeBuilder::new(SND_INO_BASE | ((card_id as u64) << 8) | minor, mk_mode(FileType::CharDev, 0o666),
                      default_inode_ops(), Arc::new(SndFileOps))
        .private(Arc::new(SndData { card_id, minor }))
        .build()
}

struct SoundNode {
    name: &'static str,
    class: &'static str,
    dev_name: &'static str,
    dev_t: (u32, u32),
    minor: u64,
}

fn alsa_nodes(card_id: u32) -> [(String, String, (u32, u32), u64); 3] {
    let base = card_id.saturating_mul(32);
    [
        (
            format!("controlC{}", card_id),
            format!("snd/controlC{}", card_id),
            (116, base),
            MINOR_CONTROL,
        ),
        (
            format!("pcmC{}D0p", card_id),
            format!("snd/pcmC{}D0p", card_id),
            (116, base.saturating_add(16)),
            MINOR_PCM_P,
        ),
        (
            format!("pcmC{}D0c", card_id),
            format!("snd/pcmC{}D0c", card_id),
            (116, base.saturating_add(24)),
            MINOR_PCM_C,
        ),
    ]
}

const OSS_PRIMARY_NODES: &[SoundNode] = &[
    SoundNode {
        name: "dsp",
        class: "sound",
        dev_name: "dsp",
        dev_t: (14, 3),
        minor: MINOR_DSP,
    },
    SoundNode {
        name: "dsp0",
        class: "sound",
        dev_name: "dsp0",
        dev_t: (14, 3),
        minor: MINOR_DSP,
    },
    SoundNode {
        name: "audio",
        class: "sound",
        dev_name: "audio",
        dev_t: (14, 4),
        minor: MINOR_AUDIO,
    },
    SoundNode {
        name: "mixer",
        class: "sound",
        dev_name: "mixer",
        dev_t: (14, 0),
        minor: MINOR_MIXER,
    },
];

fn add_sound_node(class: &'static str, name: String, dev_name: String, dev_t: (u32, u32), card_id: u32, minor: u64) -> Arc<drv::Device> {
    let factory: drv::NodeFactory = Arc::new(move || make_snd_inode(card_id, minor));
    drv::device_add(Arc::new(
        drv::Device::new(class, name, 0, 0, minor as u32)
            .with_devnode(class, dev_name, Some(dev_t))
            .with_node_factory(factory),
    ))
}

fn add_oss_node(card_id: u32, node: &SoundNode) -> Arc<drv::Device> {
    add_sound_node(
        node.class,
        String::from(node.name),
        String::from(node.dev_name),
        node.dev_t,
        card_id,
        node.minor,
    )
}

/// Sound-node ioctl entry point for the shared `sys_ioctl` dispatch chain.
/// Routes by the node minor + ioctl magic. Returns `Some(rv)` for sound
/// nodes, `None` otherwise. # C: O(1) excluding a blocking PCM transfer
pub fn handle_ioctl(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    let ino = inode.ino();
    if ino & SND_INO_MASK != SND_INO_BASE { return None; }
    let minor = ino & 0xFF;
    let group = (req >> 8) & 0xFF;
    let nr = req & 0xFF;
    let card_id = inode.private::<SndData>().map(|d| d.card_id).unwrap_or(((ino >> 8) & 0xFFFF_FFFF) as u32);
    Some(match minor {
        MINOR_PCM_P if group == PCM_MAGIC => pcm::handle(card_id, nr, arg),
        MINOR_PCM_C if group == PCM_MAGIC => capture::handle(card_id, nr, arg),
        MINOR_CONTROL if group == CTL_MAGIC => control::handle(card_id, nr, arg),
        MINOR_DSP | MINOR_AUDIO => oss::handle(card_id, false, req, arg),
        MINOR_MIXER => oss::handle(card_id, true, req, arg),
        // Unknown ioctl on a sound node → ENOTTY (don't fall through).
        _ => -(syscall::errno::Errno::Enotty.as_i32() as i64),
    })
}

/// Active ALSA card number, if a card driver has published one.
/// # C: O(1)
pub fn active_card_id() -> Option<u32> {
    CARDS.lock().first().map(|card| card.card_id)
}

/// Register the ALSA (primary) + OSS (emulation) nodes for a probed card.
/// Called from the sound card driver's probe after it has installed ops.
/// # C: O(depth)
pub fn register_card(ops_endpoint: ops::OpsEndpoint) -> Option<u32> {
    if !ops::is_owner(ops_endpoint) {
        return None;
    }
    {
        let cards = CARDS.lock();
        if let Some(card) = cards.iter().find(|card| card.ops_endpoint == ops_endpoint) {
            return Some(card.card_id);
        }
    }
    devfs::register_dir("/dev/snd");
    let card_id = NEXT_CARD_ID.fetch_add(1, Ordering::AcqRel);
    if !ops::bind_card(ops_endpoint, card_id) {
        return None;
    }
    let mut published = Vec::new();
    for (name, dev_name, dev_t, minor) in alsa_nodes(card_id) {
        published.push(add_sound_node("sound", name, dev_name, dev_t, card_id, minor));
    }
    if card_id == 0 {
        for node in OSS_PRIMARY_NODES {
            published.push(add_oss_node(card_id, node));
        }
    }
    CARDS.lock().push(CardPublication { card_id, ops_endpoint, nodes: published });
    Some(card_id)
}

/// Remove ALSA/OSS nodes for the card being removed.
/// # C: O(nodes * depth)
pub fn unregister_card(card_id: u32) -> bool {
    let nodes = {
        let mut cards = CARDS.lock();
        let Some(idx) = cards.iter().position(|card| card.card_id == card_id) else {
            return false;
        };
        cards.remove(idx).nodes
    };
    for node in nodes.iter().rev() {
        drv::device_del(node);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    static ADDED: Spinlock<Vec<(String, Option<(u32, u32)>, bool)>, SoundLockClass>
        = Spinlock::new(Vec::new());
    static REMOVED: Spinlock<Vec<String>, SoundLockClass> = Spinlock::new(Vec::new());

    fn cfg(_card_id: u32) -> Option<(u32, u32, u32, u32)> { Some((0, 0, 0, 0)) }
    fn caps(_card_id: u32) -> ops::Caps { Some((0, 0, 1, 2)) }
    fn period(_card_id: u32) -> usize { 2048 }
    fn hw_params(_card_id: u32, _rate: u8, _format: u8, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool { true }
    fn yes(_card_id: u32) -> bool { true }
    fn trigger(_card_id: u32, _start: bool) -> bool { true }
    fn submit(_card_id: u32, b: &[u8]) -> usize { b.len() }
    fn recv(_card_id: u32, b: &mut [u8]) -> usize { b.len() }

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

    fn add_hook(class: &str, name: &str, dt: Option<(u32, u32)>, factory: Option<drv::NodeFactory>) {
        if class == "sound" {
            ADDED.lock().push((String::from(name), dt, factory.is_some()));
        }
    }

    fn del_hook(name: &str) {
        REMOVED.lock().push(String::from(name));
    }

    #[test]
    fn card_nodes_are_model_owned_and_removed() {
        drv::set_devtmpfs_hook(add_hook);
        drv::set_devtmpfs_del_hook(del_hook);
        ADDED.lock().clear();
        REMOVED.lock().clear();
        while let Some(card_id) = active_card_id() { let _ = unregister_card(card_id); }
        NEXT_CARD_ID.store(0, Ordering::Release);
        ops::clear_for_tests();

        let endpoint = ops::register(&TEST_OPS).expect("ops registered");
        let card_id = register_card(endpoint).expect("card registered");
        assert_eq!(card_id, 0);
        assert_eq!(register_card(endpoint), Some(card_id), "same endpoint register is idempotent");
        let stale = ops::OpsEndpoint { owner: endpoint.owner.wrapping_add(1) };
        assert!(register_card(stale).is_none(), "stale endpoint must not reuse active card");

        let added = ADDED.lock().clone();
        assert_eq!(added.len(), alsa_nodes(card_id).len() + OSS_PRIMARY_NODES.len());
        assert!(added.iter().any(|n| n == &(String::from("snd/controlC0"), Some((116, 0)), true)));
        assert!(added.iter().any(|n| n == &(String::from("snd/pcmC0D0p"), Some((116, 16)), true)));
        assert!(added.iter().any(|n| n == &(String::from("snd/pcmC0D0c"), Some((116, 24)), true)));
        assert!(added.iter().any(|n| n == &(String::from("dsp"), Some((14, 3)), true)));
        assert!(added.iter().any(|n| n == &(String::from("dsp0"), Some((14, 3)), true)));
        assert!(added.iter().any(|n| n == &(String::from("audio"), Some((14, 4)), true)));
        assert!(added.iter().any(|n| n == &(String::from("mixer"), Some((14, 0)), true)));

        assert!(!unregister_card(card_id + 1), "wrong card id must not remove nodes");
        assert!(unregister_card(card_id));
        let removed = REMOVED.lock().clone();
        assert_eq!(removed.len(), alsa_nodes(card_id).len() + OSS_PRIMARY_NODES.len());
        assert!(removed.iter().any(|n| n == "snd/controlC0"));
        assert!(removed.iter().any(|n| n == "snd/pcmC0D0p"));
        assert!(removed.iter().any(|n| n == "snd/pcmC0D0c"));
        assert!(removed.iter().any(|n| n == "dsp"));
        assert!(removed.iter().any(|n| n == "dsp0"));
        assert!(removed.iter().any(|n| n == "audio"));
        assert!(removed.iter().any(|n| n == "mixer"));

        assert!(!unregister_card(card_id));
        assert_eq!(
            REMOVED.lock().len(),
            alsa_nodes(card_id).len() + OSS_PRIMARY_NODES.len(),
            "second unregister is idempotent"
        );
        assert!(ops::clear(endpoint));
    }

    #[test]
    fn multiple_cards_publish_independent_alsa_nodes() {
        drv::set_devtmpfs_hook(add_hook);
        drv::set_devtmpfs_del_hook(del_hook);
        ADDED.lock().clear();
        REMOVED.lock().clear();
        while let Some(card_id) = active_card_id() { let _ = unregister_card(card_id); }
        NEXT_CARD_ID.store(0, Ordering::Release);
        ops::clear_for_tests();

        let ep0 = ops::register(&TEST_OPS).expect("ops0 registered");
        let ep1 = ops::register(&TEST_OPS).expect("ops1 registered");
        let card0 = register_card(ep0).expect("card0 registered");
        let card1 = register_card(ep1).expect("card1 registered");
        assert_eq!((card0, card1), (0, 1));

        let added = ADDED.lock().clone();
        assert!(added.iter().any(|n| n == &(String::from("snd/controlC0"), Some((116, 0)), true)));
        assert!(added.iter().any(|n| n == &(String::from("snd/controlC1"), Some((116, 32)), true)));
        assert!(added.iter().any(|n| n == &(String::from("snd/pcmC1D0p"), Some((116, 48)), true)));
        assert_eq!(added.iter().filter(|n| n.0 == "dsp").count(), 1, "OSS primary alias is card0-only");

        assert!(unregister_card(card1));
        assert!(unregister_card(card0));
        assert!(ops::clear(ep1));
        assert!(ops::clear(ep0));
    }
}
