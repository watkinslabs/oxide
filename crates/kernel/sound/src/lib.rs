// `sound` — the ALSA core (snd_pcm_lib + control + the char-device ABI) for
// the virtio-snd card. The PRIMARY surface is ALSA `/dev/snd/*`
// (controlC0 + pcmC0D0p, served by the SNDRV_*_IOCTL ABI); the OSS
// `/dev/dsp`/`/dev/mixer` nodes are snd-pcm-oss emulation over the SAME
// drv-virtio-snd substream ops — the modern-Linux layering (docs/58§5–6).
// virtio-snd is the card driver (snd_pcm_ops); this crate owns the
// substream state machine + hw_params refinement + ring accounting.

#![no_std]
extern crate alloc;

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
const MINOR_CONTROL: u64 = 0x00; // controlC0
const MINOR_PCM_P:   u64 = 0x10; // pcmC0D0p (playback)
const MINOR_PCM_C:   u64 = 0x11; // pcmC0D0c (capture)
const MINOR_DSP:     u64 = 0x20; // /dev/dsp
const MINOR_AUDIO:   u64 = 0x21; // /dev/audio
const MINOR_MIXER:   u64 = 0x22; // /dev/mixer

static CARD_NODES: Spinlock<Vec<Arc<drv::Device>>, SoundLockClass> = Spinlock::new(Vec::new());
const NO_CARD_OWNER: u32 = u32::MAX;
static CARD_OWNER: AtomicU32 = AtomicU32::new(NO_CARD_OWNER);

/// Backend-private state (`i_private`) for a sound node: the device minor that
/// keys the shared read/write/ioctl dispatch (`controlC0`/`pcmC0D0p`/…). The
/// old per-inode `ino()` tag is now `SND_INO_BASE | minor` on the inode. # C: O(1)
struct SndData { minor: u64 }

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
        let minor = match inode.private::<SndData>() { Some(d) => d.minor, None => return Err(VfsError::Einval) };
        if b.is_empty() { return Ok(0); }
        match minor {
            // OSS /dev/dsp read(2) → capture (snd-pcm-oss over the same RXQ).
            MINOR_DSP | MINOR_AUDIO => Ok(oss::read(b)),
            MINOR_PCM_C             => Ok(capture::read_bytes(b)),
            // pcmC0D0p / controlC0 / mixer → no readable byte stream.
            _ => Ok(0),
        }
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let minor = match inode.private::<SndData>() { Some(d) => d.minor, None => return Err(VfsError::Einval) };
        match minor {
            MINOR_PCM_P => {
                if b.is_empty() { return Ok(0); }
                let n = pcm::write_bytes(b);
                if n == 0 { Err(VfsError::Eio) } else { Ok(n) }
            }
            MINOR_DSP | MINOR_AUDIO => {
                if b.is_empty() { return Ok(0); }
                let n = oss::write(b);
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
fn make_snd_inode(minor: u64) -> InodeRef {
    InodeBuilder::new(SND_INO_BASE | minor, mk_mode(FileType::CharDev, 0o666),
                      default_inode_ops(), Arc::new(SndFileOps))
        .private(Arc::new(SndData { minor }))
        .build()
}

struct SoundNode {
    name: &'static str,
    class: &'static str,
    dev_name: &'static str,
    dev_t: (u32, u32),
    minor: u64,
}

const SOUND_NODES: &[SoundNode] = &[
    SoundNode {
        name: "controlC0",
        class: "sound",
        dev_name: "snd/controlC0",
        dev_t: (116, 0),
        minor: MINOR_CONTROL,
    },
    SoundNode {
        name: "pcmC0D0p",
        class: "sound",
        dev_name: "snd/pcmC0D0p",
        dev_t: (116, 16),
        minor: MINOR_PCM_P,
    },
    SoundNode {
        name: "pcmC0D0c",
        class: "sound",
        dev_name: "snd/pcmC0D0c",
        dev_t: (116, 24),
        minor: MINOR_PCM_C,
    },
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

fn add_sound_node(node: &SoundNode) -> Arc<drv::Device> {
    let minor = node.minor;
    let factory: drv::NodeFactory = Arc::new(move || make_snd_inode(minor));
    drv::device_add(Arc::new(
        drv::Device::new(node.class, node.name.into(), 0, 0, node.minor as u32)
            .with_devnode(node.class, node.dev_name.into(), Some(node.dev_t))
            .with_node_factory(factory),
    ))
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
    Some(match minor {
        MINOR_PCM_P if group == PCM_MAGIC => pcm::handle(nr, arg),
        MINOR_PCM_C if group == PCM_MAGIC => capture::handle(nr, arg),
        MINOR_CONTROL if group == CTL_MAGIC => control::handle(nr, arg),
        MINOR_DSP | MINOR_AUDIO => oss::handle(false, req, arg),
        MINOR_MIXER => oss::handle(true, req, arg),
        // Unknown ioctl on a sound node → ENOTTY (don't fall through).
        _ => -(syscall::errno::Errno::Enotty.as_i32() as i64),
    })
}

/// Register the ALSA (primary) + OSS (emulation) nodes for a probed card.
/// Called from the sound card driver's probe after it has installed ops.
/// # C: O(depth)
pub fn register_card(owner: u32) -> bool {
    if ops::ops().is_none() {
        return false;
    }
    if !reserve_card(owner) {
        return false;
    }
    {
        let registered = CARD_NODES.lock();
        if !registered.is_empty() {
            return true;
        }
    }
    devfs::register_dir("/dev/snd");
    let mut published = Vec::new();
    for node in SOUND_NODES {
        published.push(add_sound_node(node));
    }
    *CARD_NODES.lock() = published;
    true
}

/// Reserve the singleton card number before the transport probe allocates or
/// publishes any user-visible state. The current sound ABI has only card 0;
/// a second transport must fail before queue state escapes into the runtime.
/// # C: O(1)
pub fn reserve_card(owner: u32) -> bool {
    if owner == NO_CARD_OWNER {
        return false;
    }
    match CARD_OWNER.compare_exchange(NO_CARD_OWNER, owner, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => true,
        Err(current) => current == owner,
    }
}

/// Device key that owns the published global sound card.
/// # C: O(1)
pub fn owner() -> Option<u32> {
    match CARD_OWNER.load(Ordering::Acquire) {
        NO_CARD_OWNER => None,
        owner => Some(owner),
    }
}

/// Remove ALSA/OSS nodes for the card being removed.
/// # C: O(nodes * depth)
pub fn unregister_card(owner: u32) -> bool {
    if CARD_OWNER.load(Ordering::Acquire) != owner {
        return false;
    }
    let nodes = {
        let mut registered = CARD_NODES.lock();
        core::mem::take(&mut *registered)
    };
    for node in nodes.iter().rev() {
        drv::device_del(node);
    }
    CARD_OWNER
        .compare_exchange(owner, NO_CARD_OWNER, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    static TEST_LOCK: AtomicU32 = AtomicU32::new(0);
    static ADDED: Spinlock<Vec<(String, Option<(u32, u32)>, bool)>, SoundLockClass>
        = Spinlock::new(Vec::new());
    static REMOVED: Spinlock<Vec<String>, SoundLockClass> = Spinlock::new(Vec::new());
    static REMOVE_EXPECTED_OWNER: AtomicU32 = AtomicU32::new(NO_CARD_OWNER);

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

    fn cfg() -> Option<(u32, u32, u32, u32)> { Some((0, 0, 0, 0)) }
    fn caps() -> ops::Caps { Some((0, 0, 1, 2)) }
    fn period() -> usize { 2048 }
    fn hw_params(_rate: u8, _format: u8, _channels: u8, _period_bytes: u32, _buffer_bytes: u32) -> bool { true }
    fn yes() -> bool { true }
    fn trigger(_start: bool) -> bool { true }
    fn submit(b: &[u8]) -> usize { b.len() }
    fn recv(b: &mut [u8]) -> usize { b.len() }

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
        let expected = REMOVE_EXPECTED_OWNER.load(Ordering::Acquire);
        if expected != NO_CARD_OWNER {
            assert_eq!(owner(), Some(expected));
        }
        REMOVED.lock().push(String::from(name));
    }

    #[test]
    fn card_nodes_are_model_owned_and_removed() {
        let _guard = test_guard();
        drv::set_devtmpfs_hook(add_hook);
        drv::set_devtmpfs_del_hook(del_hook);
        REMOVE_EXPECTED_OWNER.store(NO_CARD_OWNER, Ordering::Release);
        ADDED.lock().clear();
        REMOVED.lock().clear();
        let _ = unregister_card(0x10);
        let _ = ops::clear(0x10);

        assert!(reserve_card(0x10));
        assert!(ops::register(0x10, &TEST_OPS));
        assert!(register_card(0x10));
        assert_eq!(owner(), Some(0x10));
        assert!(register_card(0x10), "same-owner register is idempotent");
        assert!(!register_card(0x20), "different owner cannot take a live card");

        let added = ADDED.lock().clone();
        assert_eq!(added.len(), SOUND_NODES.len());
        assert!(added.iter().any(|n| n == &(String::from("snd/controlC0"), Some((116, 0)), true)));
        assert!(added.iter().any(|n| n == &(String::from("snd/pcmC0D0p"), Some((116, 16)), true)));
        assert!(added.iter().any(|n| n == &(String::from("snd/pcmC0D0c"), Some((116, 24)), true)));
        assert!(added.iter().any(|n| n == &(String::from("dsp"), Some((14, 3)), true)));
        assert!(added.iter().any(|n| n == &(String::from("dsp0"), Some((14, 3)), true)));
        assert!(added.iter().any(|n| n == &(String::from("audio"), Some((14, 4)), true)));
        assert!(added.iter().any(|n| n == &(String::from("mixer"), Some((14, 0)), true)));

        assert!(!unregister_card(0x20), "different owner cannot remove a live card");
        assert_eq!(REMOVED.lock().len(), 0);
        assert_eq!(owner(), Some(0x10));

        REMOVE_EXPECTED_OWNER.store(0x10, Ordering::Release);
        assert!(unregister_card(0x10));
        REMOVE_EXPECTED_OWNER.store(NO_CARD_OWNER, Ordering::Release);
        let removed = REMOVED.lock().clone();
        assert_eq!(removed.len(), SOUND_NODES.len());
        assert!(removed.iter().any(|n| n == "snd/controlC0"));
        assert!(removed.iter().any(|n| n == "snd/pcmC0D0p"));
        assert!(removed.iter().any(|n| n == "snd/pcmC0D0c"));
        assert!(removed.iter().any(|n| n == "dsp"));
        assert!(removed.iter().any(|n| n == "dsp0"));
        assert!(removed.iter().any(|n| n == "audio"));
        assert!(removed.iter().any(|n| n == "mixer"));

        assert!(!unregister_card(0x10));
        assert_eq!(REMOVED.lock().len(), SOUND_NODES.len(), "second unregister is idempotent");
        assert_eq!(owner(), None);
        assert!(ops::ops().is_none(), "ops must not be visible after owner release");
        let _ = ops::clear(0x10);
    }

    #[test]
    fn card_reservation_rejects_second_owner_before_publication() {
        let _guard = test_guard();
        drv::set_devtmpfs_hook(add_hook);
        drv::set_devtmpfs_del_hook(del_hook);
        REMOVE_EXPECTED_OWNER.store(NO_CARD_OWNER, Ordering::Release);
        ADDED.lock().clear();
        REMOVED.lock().clear();
        let _ = unregister_card(0x10);
        let _ = unregister_card(0x20);
        let _ = ops::clear(0x10);

        assert!(reserve_card(0x10));
        assert_eq!(owner(), Some(0x10));
        assert!(reserve_card(0x10), "same-owner reservation is idempotent");
        assert!(!reserve_card(0x20), "second owner is rejected before publication");
        assert_eq!(ADDED.lock().len(), 0, "reservation must not publish nodes");
        assert!(!ops::register(0x20, &TEST_OPS), "wrong owner cannot publish ops");

        assert!(ops::register(0x10, &TEST_OPS));
        assert!(register_card(0x10));
        assert_eq!(ADDED.lock().len(), SOUND_NODES.len());
        assert!(!register_card(0x20));
        REMOVE_EXPECTED_OWNER.store(0x10, Ordering::Release);
        assert!(unregister_card(0x10));
        REMOVE_EXPECTED_OWNER.store(NO_CARD_OWNER, Ordering::Release);
        assert_eq!(owner(), None);
        assert!(ops::ops().is_none(), "ops must not be visible after owner release");
        assert!(ops::clear(0x10));
    }
}
