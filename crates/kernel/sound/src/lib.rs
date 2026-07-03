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
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError, InodeBuilder, FileOps, default_inode_ops, mk_mode};

mod uapi;
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

/// Register the ALSA (primary) + OSS (emulation) nodes once a virtio-snd
/// card is present. Absent a card, nothing is created. # C: O(1)
pub fn init() {
    if !drv_virtio_snd::present() { return; }
    // ALSA primary surface.
    devfs::register("/dev/snd/controlC0", make_snd_inode(MINOR_CONTROL));
    devfs::register("/dev/snd/pcmC0D0p",  make_snd_inode(MINOR_PCM_P));
    devfs::register("/dev/snd/pcmC0D0c",  make_snd_inode(MINOR_PCM_C));
    // OSS compat surface (snd-pcm-oss), over the same substream.
    devfs::register("/dev/dsp",   make_snd_inode(MINOR_DSP));
    devfs::register("/dev/dsp0",  make_snd_inode(MINOR_DSP));
    devfs::register("/dev/audio", make_snd_inode(MINOR_AUDIO));
    devfs::register("/dev/mixer", make_snd_inode(MINOR_MIXER));
}

/// Remove the ALSA + OSS device nodes before tearing down the backing card.
/// # C: O(nodes * path-depth)
pub fn unregister() {
    devfs::del_device_node("/dev/snd/controlC0");
    devfs::del_device_node("/dev/snd/pcmC0D0p");
    devfs::del_device_node("/dev/snd/pcmC0D0c");
    devfs::del_device_node("/dev/dsp");
    devfs::del_device_node("/dev/dsp0");
    devfs::del_device_node("/dev/audio");
    devfs::del_device_node("/dev/mixer");
}
