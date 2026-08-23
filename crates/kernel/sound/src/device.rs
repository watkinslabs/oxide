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
const PCM_MINOR_STRIDE: u64 = 8;
const PCM_DEVICE_LIMIT: u64 = 4;
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
    pub(crate) device: crate::ops::PcmDevice,
    #[cfg(target_os = "oxide-kernel")]
    control_wait: ControlWait,
}

fn pcm_minor(device: crate::ops::PcmDevice, capture: bool) -> u64 {
    let base = if capture { MINOR_PCM_C } else { MINOR_PCM_P };
    base + u64::from(device) * PCM_MINOR_STRIDE
}

fn pcm_kind(minor: u64) -> Option<(crate::ops::PcmDevice, bool)> {
    for device in 0..PCM_DEVICE_LIMIT {
        if minor == pcm_minor(device as u32, false) { return Some((device as u32, false)); }
        if minor == pcm_minor(device as u32, true) { return Some((device as u32, true)); }
    }
    None
}

/// `file_operations` for every `/dev/snd/*` + OSS node.
struct SndFileOps;
impl FileOps for SndFileOps {
    fn mmap_shared_frame(&self, inode: &Inode, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        let data = inode.private::<SndData>().ok_or(VfsError::Einval)?;
        let pa = match pcm_kind(data.minor) {
            Some((_, true)) => crate::capture::mmap_frame(data.owner, data.device, off),
            Some((_, false)) => crate::pcm::mmap_frame(data.owner, data.device, off),
            None => None,
        };
        Ok(pa.map(|pa| vfs::SharedFrame { pa, map_ref_held: false }))
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> {
        let data = match inode.private::<SndData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        if b.is_empty() { return Ok(0); }
        match data.minor {
            MINOR_DSP | MINOR_AUDIO => Ok(crate::oss::read(data.owner, b)),
            _ if pcm_kind(data.minor).is_some_and(|(_, capture)| capture) => Ok(crate::capture::read_bytes(data.owner, data.device, b)),
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
            // A subscription changes admission, not readiness by itself: the
            // fd is readable only once an event past this reader's cursor is
            // queued.
            let (subscribed, cursor) = crate::control::events::unpack(file.private_data());
            if !subscribed { return 0; }
            return if crate::control::events::next_after(data.owner, cursor).is_some() { vfs::POLL_IN } else { 0 };
        }
        vfs::POLL_IN | vfs::POLL_OUT
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let data = match inode.private::<SndData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        match data.minor {
            _ if pcm_kind(data.minor).is_some_and(|(_, capture)| !capture) => {
                if b.is_empty() { return Ok(0); }
                let n = crate::pcm::write_bytes(data.owner, data.device, b);
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

/// Linux `snd_ctl_read`: an unsubscribed description is EBADFD, a short
/// buffer is EINVAL, an empty queue is EAGAIN for a nonblocking reader and an
/// interruptible sleep otherwise — never EOF.
fn control_read(file: &File, data: &SndData, b: &mut [u8], nonblock: bool) -> KResult<usize> {
    let (subscribed, cursor) = crate::control::events::unpack(file.private_data());
    if !subscribed { return Err(VfsError::Ebadfd); }
    if b.len() < crate::uapi::CTL_EVENT_SIZE { return Err(VfsError::Einval); }
    if let Some(seq) = crate::control::read_event(data.owner, cursor, b) {
        file.set_private_data(crate::control::events::pack(true, seq));
        return Ok(crate::uapi::CTL_EVENT_SIZE);
    }
    if nonblock { return Err(VfsError::Eagain); }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = data;
    #[cfg(target_os = "oxide-kernel")]
    {
        // The shared wait-event primitive owns publish/recheck/dequeue order,
        // including removal of the wait-list entry on the interrupted exit.
        let owner = data.owner;
        // SAFETY: syscall process context in snd_ctl_read, with no lock held
        // across the wait; the predicate only reads the card's event queue.
        let _ = unsafe {
            sched::live::wait_event_interruptible(&data.control_wait,
                || crate::control::events::next_after(owner, cursor).is_some())
        };
        match crate::control::read_event(data.owner, cursor, b) {
            Some(seq) => {
                file.set_private_data(crate::control::events::pack(true, seq));
                Ok(crate::uapi::CTL_EVENT_SIZE)
            }
            None => Err(VfsError::Erestartsys),
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    Err(VfsError::Eagain)
}

/// Every live control inode, weakly held so an event can wake its readers and
/// its epoll subscribers. Weak, so the registry never keeps an inode alive.
static CONTROL_INODES: sync::Spinlock<Vec<(crate::SoundOwnerKey, alloc::sync::Weak<Inode>)>, sync::TaskList> =
    sync::Spinlock::new(Vec::new());

/// Wake control-fd readers and pollers of `owner` after an event is queued.
/// # C: O(control inodes)
pub(crate) fn wake_control(owner: crate::SoundOwnerKey) {
    let live: Vec<InodeRef> = {
        let mut guard = CONTROL_INODES.lock();
        guard.retain(|(_, weak)| weak.strong_count() != 0);
        guard.iter().filter(|(key, _)| *key == owner).filter_map(|(_, weak)| weak.upgrade()).collect()
    };
    for inode in live {
        if let Some(subs) = inode.poll_subscribers() { subs.notify_mask(vfs::POLL_IN); }
        #[cfg(target_os = "oxide-kernel")]
        if let Some(data) = inode.private::<SndData>() { data.control_wait.wake_all(); }
    }
}

/// Build a `/dev/snd/*` (or OSS) char-device inode for `minor`.
/// # C: O(1)
pub(crate) fn make_snd_inode(owner: crate::SoundOwnerKey, card: u32, minor: u64) -> InodeRef {
    let inode = InodeBuilder::new(crate::ids::INO_TAG | ((card as Ino) << INO_CARD_SHIFT) | minor, mk_mode(FileType::CharDev, 0o666),
                      default_inode_ops(), Arc::new(SndFileOps))
        .private(Arc::new(SndData {
            owner, card, minor, device: pcm_kind(minor).map_or(0, |(device, _)| device),
            #[cfg(target_os = "oxide-kernel")]
            control_wait: ControlWait::new(),
        }))
        .poll_subs(PollSubscribers::new())
        .build();
    if minor == MINOR_CONTROL {
        let mut guard = CONTROL_INODES.lock();
        guard.retain(|(_, weak)| weak.strong_count() != 0);
        guard.push((owner, Arc::downgrade(&inode)));
    }
    inode
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
        _ if pcm_kind(minor).is_some_and(|(_, capture)| !capture) => alloc::format!("snd/pcmC{}D{}p", card, pcm_kind(minor).unwrap().0),
        _ if pcm_kind(minor).is_some_and(|(_, capture)| capture) => alloc::format!("snd/pcmC{}D{}c", card, pcm_kind(minor).unwrap().0),
        _ => alloc::format!("snd/unknownC{}M{}", card, minor),
    }
}

fn alsa_dev_t(card: u32, minor: u64) -> (u32, u32) {
    let base = card.checked_mul(32).expect("sound card minor overflow");
    match minor {
        MINOR_CONTROL => (116, base),
        _ if pcm_kind(minor).is_some_and(|(_, capture)| !capture) => (116, base + 16 + ((minor - MINOR_PCM_P) / PCM_MINOR_STRIDE) as u32 * 8),
        _ if pcm_kind(minor).is_some_and(|(_, capture)| capture) => (116, base + 24 + ((minor - MINOR_PCM_C) / PCM_MINOR_STRIDE) as u32 * 8),
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

/// # C: O(1)
pub(crate) fn rollback_published_nodes(published: &[Arc<drv::Device>]) {
    for node in published.iter().rev() {
        drv::device_del(node);
    }
}

/// # C: O(1)
pub(crate) fn publish_card_nodes(owner: crate::SoundOwnerKey, card: u32, pcm_devices: u32) -> Option<Vec<Arc<drv::Device>>> {
    let mut published = Vec::new();
    let control_name = alsa_node_name(card, MINOR_CONTROL);
    if !push_sound_node(&mut published, owner, card, "sound", control_name, alsa_dev_t(card, MINOR_CONTROL), MINOR_CONTROL) {
        rollback_published_nodes(&published);
        return None;
    }
    let mut has_playback = false;
    let mut has_capture = false;
    for device in 0..pcm_devices.min(PCM_DEVICE_LIMIT as u32) {
        let playback = crate::ops::pcm_caps_for(owner, device).is_some();
        let capture = crate::ops::cap_caps_for(owner, device).is_some();
        if playback {
            has_playback = true;
            let minor = pcm_minor(device, false);
            let dev_name = alsa_node_name(card, minor);
            if !push_sound_node(&mut published, owner, card, "sound", dev_name, alsa_dev_t(card, minor), minor) {
                rollback_published_nodes(&published);
                return None;
            }
        }
        if capture {
            has_capture = true;
            let minor = pcm_minor(device, true);
            let dev_name = alsa_node_name(card, minor);
            if !push_sound_node(&mut published, owner, card, "sound", dev_name, alsa_dev_t(card, minor), minor) {
                rollback_published_nodes(&published);
                return None;
            }
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
        _ if pcm_kind(data.minor).is_some_and(|(_, capture)| !capture) && group == PCM_MAGIC => crate::pcm::handle(data.owner, data.card, data.device, nr, arg),
        _ if pcm_kind(data.minor).is_some_and(|(_, capture)| capture) && group == PCM_MAGIC => crate::capture::handle(data.owner, data.card, data.device, nr, arg),
        MINOR_CONTROL if group == CTL_MAGIC => crate::control::handle_open(data.owner, data.card, Some(file), nr, arg),
        MINOR_DSP | MINOR_AUDIO => crate::oss::handle(data.owner, false, req, arg),
        MINOR_MIXER => crate::oss::handle(data.owner, true, req, arg),
        _ => -(syscall::errno::Errno::Enotty.as_i32() as i64),
    })
}
