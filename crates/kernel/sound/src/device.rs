use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError, default_inode_ops, mk_mode};

use crate::uapi::{CTL_MAGIC, PCM_MAGIC};

/// High-32 tag ('Snd\0') + card/minor in the low bits — routes the shared
/// ioctl dispatcher to sound nodes while `i_private` carries the owner key.
const MINOR_CONTROL: u64 = 0x00;
pub(crate) const MINOR_PCM_P: u64 = 0x10;
const MINOR_PCM_C: u64 = 0x11;
const MINOR_DSP: u64 = 0x20;
const MINOR_AUDIO: u64 = 0x21;
const MINOR_MIXER: u64 = 0x22;

/// Backend-private state (`i_private`) for a sound node: the owning card key
/// plus the device minor that routes `controlC0`/`pcmC0D0p`/… dispatch.
/// # C: O(1)
struct SndData {
    owner: crate::SoundOwnerKey,
    card: u32,
    minor: u64,
}

/// `file_operations` for every `/dev/snd/*` + OSS node.
struct SndFileOps;
impl FileOps for SndFileOps {
    fn read(&self, inode: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> {
        let data = match inode.private::<SndData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        if b.is_empty() { return Ok(0); }
        match data.minor {
            MINOR_DSP | MINOR_AUDIO => Ok(crate::oss::read(data.owner, b)),
            MINOR_PCM_C => Ok(crate::capture::read_bytes(data.owner, b)),
            _ => Ok(0),
        }
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let data = match inode.private::<SndData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        match data.minor {
            MINOR_PCM_P => {
                if b.is_empty() { return Ok(0); }
                let n = crate::pcm::write_bytes(data.owner, b);
                if n == 0 { Err(VfsError::Eio) } else { Ok(n) }
            }
            MINOR_DSP | MINOR_AUDIO => {
                if b.is_empty() { return Ok(0); }
                let n = crate::oss::write(data.owner, b);
                if n == 0 { Err(VfsError::Eio) } else { Ok(n) }
            }
            MINOR_MIXER => Err(VfsError::Enodev),
            _ => Err(VfsError::Eio),
        }
    }
}

/// Build a `/dev/snd/*` (or OSS) char-device inode for `minor`.
/// # C: O(1)
fn make_snd_inode(owner: crate::SoundOwnerKey, card: u32, minor: u64) -> InodeRef {
    InodeBuilder::new(crate::ids::INO_TAG | ((card as Ino) << 8) | minor, mk_mode(FileType::CharDev, 0o666),
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

fn add_sound_node(owner: crate::SoundOwnerKey, card: u32, class: &'static str, dev_name: String, dev_t: (u32, u32), minor: u64) -> Option<Arc<drv::Device>> {
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
    owner: crate::SoundOwnerKey,
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

pub(crate) fn rollback_published_nodes(published: &[Arc<drv::Device>]) {
    for node in published.iter().rev() {
        drv::device_del(node);
    }
}

pub(crate) fn publish_card_nodes(owner: crate::SoundOwnerKey, card: u32, has_playback: bool, has_capture: bool) -> Option<Vec<Arc<drv::Device>>> {
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
        if matches!(node.minor, MINOR_DSP | MINOR_AUDIO) && !has_playback && !has_capture { continue; }
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
/// nodes, `None` otherwise.
/// # C: O(1) excluding a blocking PCM transfer
pub fn handle_ioctl(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    let ino = inode.ino();
    if ino & crate::ids::INO_MASK != crate::ids::INO_TAG { return None; }
    let data = match inode.private::<SndData>() {
        Some(data) => data,
        None => return Some(-(syscall::errno::Errno::Einval.as_i32() as i64)),
    };
    let group = (req >> 8) & 0xFF;
    let nr = req & 0xFF;
    Some(match data.minor {
        MINOR_PCM_P if group == PCM_MAGIC => crate::pcm::handle(data.owner, data.card, nr, arg),
        MINOR_PCM_C if group == PCM_MAGIC => crate::capture::handle(data.owner, data.card, nr, arg),
        MINOR_CONTROL if group == CTL_MAGIC => crate::control::handle(data.owner, data.card, nr, arg),
        MINOR_DSP | MINOR_AUDIO => crate::oss::handle(data.owner, false, req, arg),
        MINOR_MIXER => crate::oss::handle(data.owner, true, req, arg),
        _ => -(syscall::errno::Errno::Enotty.as_i32() as i64),
    })
}
