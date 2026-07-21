use alloc::sync::Arc;

use vfs::{
    default_inode_ops, mk_mode, File, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult,
    PollSubscribers, VfsError, POLL_IN, POLL_OUT,
};

use crate::devfs::shared::{
    evdev_id, file_token, grabbed_by_other, release_grab, EvdevData, EVDEV_FILE_REVOKED,
    EVDEV_INO_BASE, EVDEV_NODES,
};
use crate::consts::{EVENT_MINOR_BASE, INPUT_MAJOR};
use crate::evdev_queue::MAX_EVDEV;

#[cfg(target_os = "oxide-kernel")]
fn refresh_events() { crate::drain::poll_all(); }

#[cfg(not(target_os = "oxide-kernel"))]
fn refresh_events() {}

/// `file_operations` for an evdev node.
struct EvdevFileOps;

impl FileOps for EvdevFileOps {
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match evdev_id(inode) {
            Some(id) => id,
            None => return Ok(0),
        };
        if buf.len() < INPUT_EVENT_BYTES {
            return Ok(0);
        }
        refresh_events();
        let n = unsafe { crate::evdev_queue::queue(id).read_blocking(buf) };
        Ok(n)
    }

    fn read_file(&self, file: &File, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match evdev_id(file.inode()) {
            Some(id) => id,
            None => return Ok(0),
        };
        if file.private_data() & EVDEV_FILE_REVOKED != 0 {
            return Err(VfsError::Enodev);
        }
        if buf.len() < INPUT_EVENT_BYTES {
            return Ok(0);
        }
        let token = file_token(file);
        loop {
            refresh_events();
            if !grabbed_by_other(id, token) {
                return Ok(unsafe { crate::evdev_queue::queue(id).read_blocking(buf) });
            }
            unsafe { crate::evdev_queue::queue(id).waiters.park(); }
            #[cfg(target_os = "oxide-kernel")]
            unsafe {
                sched::live::schedule::schedule();
            }
            #[cfg(test)]
            return Err(VfsError::Eagain);
        }
    }

    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match evdev_id(inode) {
            Some(id) => id,
            None => return Ok(0),
        };
        if buf.len() < INPUT_EVENT_BYTES {
            return Ok(0);
        }
        refresh_events();
        match crate::evdev_queue::queue(id).try_pop_bytes(buf) {
            Some(n) => Ok(n),
            None => Err(VfsError::Eagain),
        }
    }

    fn read_nonblock_file(&self, file: &File, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match evdev_id(file.inode()) {
            Some(id) => id,
            None => return Ok(0),
        };
        if file.private_data() & EVDEV_FILE_REVOKED != 0 {
            return Err(VfsError::Enodev);
        }
        if buf.len() < INPUT_EVENT_BYTES {
            return Ok(0);
        }
        if grabbed_by_other(id, file_token(file)) {
            return Err(VfsError::Eagain);
        }
        refresh_events();
        match crate::evdev_queue::queue(id).try_pop_bytes(buf) {
            Some(n) => Ok(n),
            None => Err(VfsError::Eagain),
        }
    }

    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> {
        Err(VfsError::Eio)
    }

    fn poll(&self, inode: &Inode) -> u32 {
        let id = match evdev_id(inode) {
            Some(id) => id,
            None => return POLL_OUT,
        };
        refresh_events();
        if crate::evdev_queue::queue(id).is_empty() {
            POLL_OUT
        } else {
            POLL_IN | POLL_OUT
        }
    }

    fn poll_open_file(&self, file: &File) -> u32 {
        if file.private_data() & EVDEV_FILE_REVOKED != 0 {
            return POLL_OUT | vfs::POLL_HUP;
        }
        let id = match evdev_id(file.inode()) {
            Some(id) => id,
            None => return POLL_OUT,
        };
        refresh_events();
        if grabbed_by_other(id, file_token(file)) || crate::evdev_queue::queue(id).is_empty() {
            POLL_OUT
        } else {
            POLL_IN | POLL_OUT
        }
    }

    fn on_release_file(&self, file: &File) {
        if let Some(id) = evdev_id(file.inode()) {
            release_grab(id, file_token(file));
        }
    }
}

pub fn make_evdev_inode(id: u32) -> InodeRef {
    let ino = EVDEV_INO_BASE | (0x01 + id as Ino);
    let inode = InodeBuilder::new(
        ino,
        mk_mode(FileType::CharDev, 0o666),
        default_inode_ops(),
        Arc::new(EvdevFileOps),
    )
    .private(Arc::new(EvdevData { id }))
    // logind reads st_rdev and passes it to TakeDevice(major, minor).  This
    // bespoke inode must therefore carry the same Linux evdev dev_t as the
    // driver-model device, rather than the default 0:0.
    .rdev(vfs::Devt::new(INPUT_MAJOR, EVENT_MINOR_BASE + id).raw())
    .poll_subs(PollSubscribers::new())
    .build();
    if (id as usize) < MAX_EVDEV {
        EVDEV_NODES.lock()[id as usize] = Some(inode.clone());
    }
    inode
}

pub fn notify_evdev_subs(id: u32) {
    if (id as usize) >= MAX_EVDEV {
        return;
    }
    let node = EVDEV_NODES.lock()[id as usize].clone();
    if let Some(inode) = node {
        if let Some(subs) = inode.poll_subscribers() {
            subs.notify();
        }
    }
}
