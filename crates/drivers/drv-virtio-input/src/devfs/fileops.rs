use alloc::sync::Arc;

use vfs::{
    default_inode_ops, mk_mode, File, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult,
    PollSubscribers, VfsError, POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT,
};

use crate::consts::{
    EVENT_MINOR_BASE, EVDEV_FIRST_INO_OFFSET, EVDEV_NODE_PERMISSIONS, INPUT_MAJOR,
};
use crate::devfs::shared::{
    evdev_open, install_open, open_endpoint, release_open, EvdevData, EvdevEndpoint,
    EVDEV_INO_BASE,
};
#[cfg(test)]
use crate::devfs::shared::current_endpoint;
use crate::evdev_queue::{output_value_from_bytes, INPUT_EVENT_BYTES};

#[cfg(target_os = "oxide-kernel")]
fn refresh_events() { crate::drain::poll_all(); }

#[cfg(not(target_os = "oxide-kernel"))]
fn refresh_events() {}

/// Does the reader carry an unblocked pending signal? A blocking evdev read
/// that ignores this is unkillable — it survives even SIGKILL, because the
/// only other thing that ends the sleep is an input event that may never come.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn signal_pending() -> bool {
    use core::sync::atomic::Ordering;
    match sched::live::current() {
        Some(task) => {
            task.pending_signals() & !task.sigmask.load(Ordering::Acquire) != 0
        }
        None => false,
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn signal_pending() -> bool { false }

struct EvdevFileOps;

impl EvdevFileOps {
    fn live_open<'a>(&self, file: &'a File) -> KResult<&'a super::shared::EvdevOpen> {
        let opened = evdev_open(file).ok_or(VfsError::Enodev)?;
        if !opened.is_live() {
            return Err(VfsError::Enodev);
        }
        Ok(opened)
    }
}

impl FileOps for EvdevFileOps {
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(VfsError::Enodev)
    }

    fn read_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let opened = self.live_open(file)?;
        if buf.is_empty() { return Ok(0); }
        if buf.len() < INPUT_EVENT_BYTES { return Err(VfsError::Einval); }
        loop {
            if !opened.is_live() {
                return Err(VfsError::Enodev);
            }
            refresh_events();
            if let Some(len) = opened.try_pop_bytes(buf) { return Ok(len); }
            if signal_pending() { return Err(VfsError::Eintr); }
            // SAFETY: process-context evdev read publishes the current task before scheduling.
            unsafe { opened.queue().waiters.park(); }
            if !opened.is_live() || opened.has_pending() || signal_pending() {
                opened.queue().waiters.cancel_current_park();
                continue;
            }
            #[cfg(target_os = "oxide-kernel")]
            // SAFETY: WaitList::park marked the running task sleeping and released all locks.
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(test)]
            return Err(VfsError::Eagain);
        }
    }

    fn read_nonblock(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(VfsError::Enodev)
    }

    fn read_nonblock_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let opened = self.live_open(file)?;
        if buf.is_empty() { return Ok(0); }
        if buf.len() < INPUT_EVENT_BYTES { return Err(VfsError::Einval); }
        refresh_events();
        if !opened.is_live() {
            return Err(VfsError::Enodev);
        }
        opened.try_pop_bytes(buf).ok_or(VfsError::Eagain)
    }

    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Eio)
    }

    fn write_file(&self, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        let opened = self.live_open(file)?;
        if buf.is_empty() {
            return Ok(0);
        }
        if !buf.len().is_multiple_of(INPUT_EVENT_BYTES) {
            return Err(VfsError::Einval);
        }
        let requested = input::OutputBatch {
            events: buf.chunks_exact(INPUT_EVENT_BYTES)
                .filter_map(output_value_from_bytes)
                .collect(),
        };
        let identity = opened.identity();
        input::apply_output_by_identity(
            identity.device_key,
            identity.input_id,
            identity.evdev_id,
            &requested,
        ).ok_or(VfsError::Enodev)?;
        Ok(buf.len())
    }

    fn write_nonblock_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_file(file, off, buf)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, _inode: &Inode) -> u32 { POLL_ERR }

    fn poll_open_file(&self, file: &File) -> u32 {
        let Some(opened) = evdev_open(file) else { return POLL_ERR | POLL_HUP; };
        refresh_events();
        let pending = opened.has_pending();
        if !opened.is_live() {
            return POLL_ERR | POLL_HUP | if pending { POLL_IN } else { 0 };
        }
        POLL_OUT | if pending { POLL_IN } else { 0 }
    }

    fn poll_subscribers(&self, file: &File) -> Option<Arc<PollSubscribers>> {
        Some(evdev_open(file)?.queue().poll_subscribers())
    }

    fn on_open_file(&self, file: &File) -> KResult<()> {
        let endpoint = open_endpoint(file.inode()).ok_or(VfsError::Enodev)?;
        let opened = endpoint.open().ok_or(VfsError::Enodev)?;
        install_open(file, opened);
        Ok(())
    }

    fn on_release_file(&self, file: &File) {
        release_open(file);
    }
}

pub(crate) fn make_evdev_inode_for(endpoint: Arc<EvdevEndpoint>) -> InodeRef {
    let id = endpoint.identity().evdev_id;
    let ino = EVDEV_INO_BASE | (EVDEV_FIRST_INO_OFFSET + id as Ino);
    InodeBuilder::new(
        ino,
        mk_mode(FileType::CharDev, EVDEV_NODE_PERMISSIONS),
        default_inode_ops(),
        Arc::new(EvdevFileOps),
    )
    .private(Arc::new(EvdevData { endpoint }))
    .rdev(vfs::Devt::new(INPUT_MAJOR, EVENT_MINOR_BASE + id).raw())
    .build()
}

#[cfg(test)]
/// Build one test inode for the current or synthesized endpoint generation.
/// # C: O(1)
pub fn make_evdev_inode(id: u32) -> InodeRef {
    let model = input::device(id);
    if let Some(endpoint) = current_endpoint(id) {
        let identity = endpoint.identity();
        let matches = model.as_ref().is_some_and(|dev| {
            dev.device_key == identity.device_key
                && dev.input_id == identity.input_id
                && dev.evdev_id == identity.evdev_id
        });
        if matches || model.is_none() {
            return make_evdev_inode_for(endpoint);
        }
        let _ = super::shared::unpublish_endpoint(id);
    }
    let endpoint = match model {
        Some(dev) => EvdevEndpoint::new(dev.device_key, dev.input_id, dev.evdev_id),
        None => super::shared::test_endpoint(id, u32::MAX - id),
    };
    assert!(super::shared::publish_endpoint(Arc::clone(&endpoint)));
    make_evdev_inode_for(endpoint)
}
