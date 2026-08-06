use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{File, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult,
          PollSubscribers, VfsError, default_inode_ops, mk_mode};

use crate::uapi::{CTL_MAGIC, PCM_MAGIC};

#[cfg(target_os = "oxide-kernel")]
type ControlWait = sched::live::WaitList;

// Device minor within one card. Carried in `i_private` (what routes the
// dispatch) and mirrored into the low bits of the inode number under sound's
// declared tag, where it names nothing and decides nothing.
pub(crate) const MINOR_CONTROL: u64 = 0x00;
pub(crate) const MINOR_PCM_P: u64 = 0x10;
pub(crate) const MINOR_PCM_C: u64 = 0x11;
pub(crate) const MINOR_DSP: u64 = 0x20;
pub(crate) const MINOR_AUDIO: u64 = 0x21;
pub(crate) const MINOR_MIXER: u64 = 0x22;
/// Bit position of the card number in the low half of a sound inode number.
const INO_CARD_SHIFT: u32 = 8;

/// Backend-private state (`i_private`) for a sound node: the owning card key
/// plus the device minor that routes `controlC0`/`pcmC0D0p`/… dispatch.
/// # C: O(1)
pub(crate) struct SndData {
    pub(crate) owner: crate::SoundOwnerKey,
    pub(crate) card: u32,
    pub(crate) minor: u64,
    #[cfg(target_os = "oxide-kernel")]
    control_wait: ControlWait,
}

/// `file_operations` for every `/dev/snd/*` + OSS node.
struct SndFileOps;
impl FileOps for SndFileOps {
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> {
        let data = match inode.private::<SndData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        if b.is_empty() { return Ok(0); }
        match data.minor {
            MINOR_DSP | MINOR_AUDIO => Ok(crate::oss::read(data.owner, b)),
            MINOR_PCM_C => Ok(crate::capture::read_bytes(data.owner, b)),
            _ => Ok(0),
        }
    }
    fn read_file(&self, file: &File, off: u64, b: &mut [u8]) -> KResult<usize> {
        let data = file.inode().private::<SndData>().ok_or(VfsError::Einval)?;
        if data.minor == MINOR_CONTROL { return control_read(file, data, b, false); }
        self.read(file.inode(), off, b)
    }
    fn read_nonblock_file(&self, file: &File, off: u64, b: &mut [u8]) -> KResult<usize> {
        let data = file.inode().private::<SndData>().ok_or(VfsError::Einval)?;
        if data.minor == MINOR_CONTROL { return control_read(file, data, b, true); }
        self.read(file.inode(), off, b)
    }
    fn poll_open_file(&self, file: &File) -> u32 {
        let Some(data) = file.inode().private::<SndData>() else { return 0 };
        if data.minor == MINOR_CONTROL {
            // No driver-backed control elements means no events can be queued.
            // A subscription changes admission, not readiness by itself.
            return 0;
        }
        vfs::POLL_IN | vfs::POLL_OUT
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

/// Linux `snd_ctl_read` for the currently empty event implementation. The
/// queue becomes real alongside driver-backed controls; until then the exact
/// empty-queue contract is still observable and load-bearing: nonblocking
/// readers get EAGAIN and blocking readers sleep interruptibly, never EOF.
fn control_read(file: &File, data: &SndData, b: &mut [u8], nonblock: bool) -> KResult<usize> {
    if file.private_data() == 0 { return Err(VfsError::Ebadfd); }
    if b.len() < crate::uapi::CTL_EVENT_SIZE { return Err(VfsError::Einval); }
    if nonblock { return Err(VfsError::Eagain); }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = data;
    #[cfg(target_os = "oxide-kernel")]
    {
        // No events exist yet, so only signal delivery can finish this wait.
        // The shared wait-event primitive owns publish/recheck/dequeue order,
        // including removal of the wait-list entry on the interrupted exit.
        // SAFETY: syscall process context, with no lock held across the wait.
        let _ = unsafe { sched::live::wait_event_interruptible(&data.control_wait, || false) };
        Err(VfsError::Erestartsys)
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    Err(VfsError::Eagain)
}

/// Build a `/dev/snd/*` (or OSS) char-device inode for `minor`.
/// # C: O(1)
pub(crate) fn make_snd_inode(owner: crate::SoundOwnerKey, card: u32, minor: u64) -> InodeRef {
    InodeBuilder::new(crate::ids::INO_TAG | ((card as Ino) << INO_CARD_SHIFT) | minor, mk_mode(FileType::CharDev, 0o666),
                      default_inode_ops(), Arc::new(SndFileOps))
        .private(Arc::new(SndData {
            owner, card, minor,
            #[cfg(target_os = "oxide-kernel")]
            control_wait: ControlWait::new(),
        }))
        .poll_subs(PollSubscribers::new())
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

/// Is this inode a sound node, and which one? Linux answers by the file's
/// `snd_*_f_ops`; the inode NUMBER cannot. Gating on the tag first and reading
/// the backend state second CONSUMED the ioctl with EINVAL for any inode that
/// merely carried the tag, instead of letting the dispatch chain reach the
/// stage that owns it. `make_snd_inode` is the only place that installs
/// [`SndData`]. # C: O(1)
pub(crate) fn snd_data_of(inode: &InodeRef) -> Option<&SndData> {
    inode.private::<SndData>()
}

/// Sound-node ioctl entry point for the shared `sys_ioctl` dispatch chain.
/// Routes by the node minor + ioctl magic. Returns `Some(rv)` for sound
/// nodes, `None` otherwise.
/// # C: O(1) excluding a blocking PCM transfer
pub fn handle_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    let data = match snd_data_of(file.inode()) { Some(data) => data, None => return None };
    let group = (req >> 8) & 0xFF;
    let nr = req & 0xFF;
    Some(match data.minor {
        MINOR_PCM_P if group == PCM_MAGIC => crate::pcm::handle(data.owner, data.card, nr, arg),
        MINOR_PCM_C if group == PCM_MAGIC => crate::capture::handle(data.owner, data.card, nr, arg),
        MINOR_CONTROL if group == CTL_MAGIC => crate::control::handle_open(data.owner, data.card, Some(file), nr, arg),
        MINOR_DSP | MINOR_AUDIO => crate::oss::handle(data.owner, false, req, arg),
        MINOR_MIXER => crate::oss::handle(data.owner, true, req, arg),
        _ => -(syscall::errno::Errno::Enotty.as_i32() as i64),
    })
}
