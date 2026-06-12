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
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

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

/// ALSA `/dev/snd/pcmC0D0p` playback node. ioctls → the PCM core; `write(2)`
/// → the byte-stream transfer; `read(2)` is capture (a follow-up).
struct PcmPlaybackInode;
impl Inode for PcmPlaybackInode {
    fn ino(&self) -> Ino { SND_INO_BASE | MINOR_PCM_P }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> {
        if b.is_empty() { return Ok(0); }
        let n = pcm::write_bytes(b);
        if n == 0 { Err(VfsError::Eio) } else { Ok(n) }
    }
}

/// ALSA `/dev/snd/pcmC0D0c` capture node. ioctls → the capture core;
/// `read(2)` → the byte-stream capture transfer.
struct PcmCaptureInode;
impl Inode for PcmCaptureInode {
    fn ino(&self) -> Ino { SND_INO_BASE | MINOR_PCM_C }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, b: &mut [u8]) -> KResult<usize> {
        if b.is_empty() { return Ok(0); }
        Ok(capture::read_bytes(b))
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// ALSA `/dev/snd/controlC0` node. ioctl-only.
struct ControlInode;
impl Inode for ControlInode {
    fn ino(&self) -> Ino { SND_INO_BASE | MINOR_CONTROL }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// OSS `/dev/dsp` + `/dev/audio` node. `write(2)` → the OSS transfer; ioctls
/// → SNDCTL_DSP_*. `/dev/audio` (minor AUDIO) seeds µ-law/8 kHz on open.
struct DspInode { minor: u64 }
impl Inode for DspInode {
    fn ino(&self) -> Ino { SND_INO_BASE | self.minor }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, b: &mut [u8]) -> KResult<usize> {
        // OSS /dev/dsp read(2) → capture (snd-pcm-oss over the same RXQ).
        if b.is_empty() { return Ok(0); }
        Ok(oss::read(b))
    }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> {
        if b.is_empty() { return Ok(0); }
        let n = oss::write(b);
        if n == 0 { Err(VfsError::Eio) } else { Ok(n) }
    }
}

/// OSS `/dev/mixer` node. ioctl-only (master level).
struct MixerInode;
impl Inode for MixerInode {
    fn ino(&self) -> Ino { SND_INO_BASE | MINOR_MIXER }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
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
    devfs::register("/dev/snd/controlC0", Arc::new(ControlInode) as InodeRef);
    devfs::register("/dev/snd/pcmC0D0p",  Arc::new(PcmPlaybackInode) as InodeRef);
    devfs::register("/dev/snd/pcmC0D0c",  Arc::new(PcmCaptureInode) as InodeRef);
    // OSS compat surface (snd-pcm-oss), over the same substream.
    devfs::register("/dev/dsp",   Arc::new(DspInode { minor: MINOR_DSP }) as InodeRef);
    devfs::register("/dev/dsp0",  Arc::new(DspInode { minor: MINOR_DSP }) as InodeRef);
    devfs::register("/dev/audio", Arc::new(DspInode { minor: MINOR_AUDIO }) as InodeRef);
    devfs::register("/dev/mixer", Arc::new(MixerInode) as InodeRef);
}
