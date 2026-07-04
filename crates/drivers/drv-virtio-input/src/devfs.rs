// /dev/input/event<id> evdev substrate per `35§R01`. Full Linux evdev ABI:
// blocking/non-blocking reads of 24-byte `input_event` records, `->poll`
// (POLLIN only when a record is queued), per-fd poll/epoll subscribers, and
// the EVIOCG* identification/capability ioctls answered from the device's
// real virtio config-space capability bitmaps (drv::VirtioInputDev).

use alloc::sync::Arc;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError, POLL_IN, POLL_OUT,
          InodeBuilder, FileOps, default_inode_ops, mk_mode, PollSubscribers};
use sync::{Spinlock, TaskList as NodesLockClass};

use crate::evdev_queue::MAX_EVDEV;

const EVDEV_INO_BASE: Ino = 0x7400_0000;

/// Backend-private state (`i_private`) for `/dev/input/event<id>`: the evdev
/// id that keys the per-device queue. The per-inode `ino()` tag is
/// `EVDEV_INO_BASE | (1 + id)` on the inode. # C: O(1)
pub struct EvdevData { pub id: u32 }

/// `id -> node inode` registry. The canonical `PollSubscribers` now lives on
/// the inode (`Inode::poll_subs`, where `epoll_ctl(ADD)` registers); the drain
/// reaches it through here to `notify()` on push. `None` until the owning
/// virtio-input device probes and publishes its event node. # C: O(1)
static EVDEV_NODES: Spinlock<[Option<InodeRef>; MAX_EVDEV], NodesLockClass>
    = Spinlock::new([const { None }; MAX_EVDEV]);

/// `id -> drv::Device` for model-owned evdev publication. The node itself is
/// still bespoke, but `/dev/input/eventN` is minted and removed by
/// `drv::device_add` / `drv::device_del` through the devtmpfs hook.
static EVDEV_DEVICES: Spinlock<[Option<Arc<drv::Device>>; MAX_EVDEV], NodesLockClass>
    = Spinlock::new([const { None }; MAX_EVDEV]);

/// `file_operations` for an evdev node — read pops 24-byte `input_event`
/// records from the device queue keyed by the `id` in `i_private`; poll
/// reports POLLIN only when a record is queued.
struct EvdevFileOps;
impl FileOps for EvdevFileOps {
    /// Blocking pop of one input_event record (24 B). Parks the caller on
    /// this device's queue waiters when empty; resumes when virtio-input
    /// pushes the next event. Reads of less than one record return 0.
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match inode.private::<EvdevData>() { Some(d) => d.id, None => return Ok(0) };
        if buf.len() < INPUT_EVENT_BYTES { return Ok(0); }
        // SAFETY: caller is the running task on this CPU; read_blocking parks safely via WaitList and reschedules.
        let n = unsafe { crate::evdev_queue::queue(id).read_blocking(buf) };
        Ok(n)
    }

    /// Non-blocking variant per O_NONBLOCK.
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match inode.private::<EvdevData>() { Some(d) => d.id, None => return Ok(0) };
        if buf.len() < INPUT_EVENT_BYTES { return Ok(0); }
        match crate::evdev_queue::queue(id).try_pop_bytes(buf) {
            Some(n) => Ok(n),
            None    => Err(VfsError::Eagain),
        }
    }

    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }

    /// Linux evdev_poll: EPOLLOUT always (evdev sink never blocks writes),
    /// EPOLLIN only when at least one record is queued. sys_poll masks the
    /// result against the caller's requested events, so a `poll(POLLIN)`
    /// blocks until the drain pushes the next event. # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let id = match inode.private::<EvdevData>() { Some(d) => d.id, None => return POLL_OUT };
        if crate::evdev_queue::queue(id).is_empty() { POLL_OUT }
        else { POLL_IN | POLL_OUT }
    }
}

/// Build the `/dev/input/event<id>` inode: `S_IFCHR|0o666`, `ino = EVDEV_INO_BASE
/// | (1 + id)` (the routing tag the EVIOC* ioctl path reads), the per-fd epoll
/// subscriber list (`epoll_ctl(ADD)` lands here; the drain wakes it via
/// [`notify_evdev_subs`]), the shared `EvdevFileOps` data path, lookup →
/// `ENOTDIR` (default i_op). Registers the node in [`EVDEV_NODES`]. # C: O(1)
pub fn make_evdev_inode(id: u32) -> InodeRef {
    let ino = EVDEV_INO_BASE | (0x01 + id as Ino);
    let inode = InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0o666), default_inode_ops(), Arc::new(EvdevFileOps))
        .private(Arc::new(EvdevData { id }))
        .poll_subs(PollSubscribers::new())
        .build();
    if (id as usize) < MAX_EVDEV { EVDEV_NODES.lock()[id as usize] = Some(inode.clone()); }
    inode
}

/// Wake the epoll/poll subscribers registered on evdev `id`'s node inode.
/// Called by the queue's push path after enqueuing an event (the inode owns
/// the canonical `PollSubscribers`). No-op if no node was built for `id`.
/// # C: O(subscribers)
pub fn notify_evdev_subs(id: u32) {
    if (id as usize) >= MAX_EVDEV { return; }
    let node = EVDEV_NODES.lock()[id as usize].clone();
    if let Some(inode) = node {
        if let Some(subs) = inode.poll_subscribers() { subs.notify(); }
    }
}

// ---- Linux asm-generic/ioctl.h decode --------------------------------------
#[inline] fn ioc_nr(req: u64)   -> u32 { (req & 0xFF) as u32 }
#[inline] fn ioc_type(req: u64) -> u32 { ((req >> 8) & 0xFF) as u32 }
#[inline] fn ioc_size(req: u64) -> usize { ((req >> 16) & 0x3FFF) as usize }

/// Copy `src` (capped at the ioctl's declared size) into the user buffer at
/// `arg`. Returns the byte count (Linux EVIOCG* convention).
/// # SAFETY: `arg` validated in `[1, USER_VA_END)` by the caller; writes
/// `min(src.len, cap)` bytes within that user-owned window, nothing else.
unsafe fn uwrite(arg: u64, src: &[u8], cap: usize) -> i64 {
    let n = src.len().min(cap);
    // SAFETY: per fn contract — arg+i stays inside the validated user window for i < n ≤ cap.
    unsafe { for i in 0..n { core::ptr::write_volatile((arg + i as u64) as *mut u8, src[i]); } }
    n as i64
}

/// Zero-fill `cap` bytes at the user buffer (unknown EV_BIT class / absent
/// key/led state — Linux returns a zeroed bitmap, not an error).
/// # SAFETY: `arg` validated in `[1, USER_VA_END)`; writes `cap` zero bytes
/// within that user-owned window.
unsafe fn uzero(arg: u64, cap: usize) -> i64 {
    // SAFETY: per fn contract — arg+i stays inside the validated user window for i < cap.
    unsafe { for i in 0..cap { core::ptr::write_volatile((arg + i as u64) as *mut u8, 0); } }
    cap as i64
}

/// EVIOC* ioctl handler. Returns `Some(rv)` when the request is recognised;
/// `None` to let the generic CharDev path run. Answers identification +
/// capability queries from the device's real virtio config-space record.
/// # C: O(1)
pub fn handle_evdev_ioctl(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    let ino = inode.ino();
    if (ino & !0xFF) != EVDEV_INO_BASE || (ino & 0xFF) == 0 { return None; }
    use syscall::errno::Errno;
    if ioc_type(req) != b'E' as u64 as u32 { return None; }
    let nr = ioc_nr(req);

    // EVIOCSCLOCKID / EVIOCGRAB / EVIOCREVOKE — state-changing, no readback.
    // Ack so libinput/X11 grab logic proceeds (single-reader model).
    const EVIOCGRAB_NR:     u32 = 0x90;
    const EVIOCREVOKE_NR:   u32 = 0x91;
    const EVIOCSCLOCKID_NR: u32 = 0xa0;
    if nr == EVIOCGRAB_NR || nr == EVIOCREVOKE_NR || nr == EVIOCSCLOCKID_NR {
        return Some(0);
    }

    if arg == 0 || arg >= hal::USER_VA_END {
        return Some(-(Errno::Efault.as_i32() as i64));
    }
    let size = ioc_size(req);
    let evdev_id = ((ino & 0xFF) - 1) as u32;
    let dev = crate::device(evdev_id);

    // SAFETY: arg validated in [1, USER_VA_END); each uwrite/uzero bounds its
    // write by the ioctl-declared size within that user-owned window.
    let rv: i64 = unsafe { match nr {
        0x01 => { // EVIOCGVERSION → int EV_VERSION
            let v: u32 = 0x01_0001;
            uwrite(arg, &v.to_le_bytes(), size.max(4)); 0
        }
        0x02 => { // EVIOCGID → struct input_id { bustype, vendor, product, version }
            let ids = dev.as_ref().map(|d| d.ids).unwrap_or_default();
            let mut b = [0u8; 8];
            b[0..2].copy_from_slice(&ids.bustype.to_le_bytes());
            b[2..4].copy_from_slice(&ids.vendor.to_le_bytes());
            b[4..6].copy_from_slice(&ids.product.to_le_bytes());
            b[6..8].copy_from_slice(&ids.version.to_le_bytes());
            uwrite(arg, &b, size.max(8)); 0
        }
        0x06 => { // EVIOCGNAME(len) → device name, NUL-terminated
            match dev.as_ref() {
                Some(d) => {
                    let len = d.name_len.min(d.name.len());
                    let mut b = [0u8; 129];
                    b[..len].copy_from_slice(&d.name[..len]);
                    // emit name bytes + NUL, capped at requested size
                    uwrite(arg, &b[..len + 1], size)
                }
                None => uzero(arg, size),
            }
        }
        0x07 => uzero(arg, size), // EVIOCGPHYS — no physical-location string
        0x08 => { // EVIOCGUNIQ(len) → serial / unique id
            match dev.as_ref() {
                Some(d) if d.serial_len > 0 => {
                    let len = d.serial_len.min(d.serial.len());
                    let mut b = [0u8; 129];
                    b[..len].copy_from_slice(&d.serial[..len]);
                    uwrite(arg, &b[..len + 1], size)
                }
                _ => uzero(arg, size),
            }
        }
        0x09 => { // EVIOCGPROP(len) → INPUT_PROP_* bitmap
            match dev.as_ref() {
                Some(d) => uwrite(arg, &d.prop_bits, size),
                None    => uzero(arg, size),
            }
        }
        0x18 | 0x19 | 0x1a | 0x1b => uzero(arg, size), // GKEY/GLED/GSND/GSW state
        0x20..=0x3f => { // EVIOCGBIT(ev, len) → capability bitmap for ev type
            let ev = nr - 0x20;
            match (dev.as_ref(), ev) {
                (Some(d), 0x00) => uwrite(arg, &d.ev_bits, size),
                (Some(d), 0x01) => uwrite(arg, &d.key_bits.bits, size), // EV_KEY
                (Some(d), 0x02) => uwrite(arg, &d.rel_bits.bits, size), // EV_REL
                (Some(d), 0x03) => uwrite(arg, &d.abs_bits.bits, size), // EV_ABS
                (Some(d), 0x11) => uwrite(arg, &d.led_bits.bits, size), // EV_LED
                _               => uzero(arg, size),
            }
        }
        0x40..=0x7f => { // EVIOCGABS(axis) → struct input_absinfo (24 B)
            let axis = (nr - 0x40) as usize;
            let ai = dev.as_ref().and_then(|d| d.abs_info.get(axis).copied().flatten());
            let mut b = [0u8; 24]; // value=0 (current pos unknown), then min/max/fuzz/flat/res
            if let Some(a) = ai {
                b[4..8].copy_from_slice(&a.min.to_le_bytes());
                b[8..12].copy_from_slice(&a.max.to_le_bytes());
                b[12..16].copy_from_slice(&a.fuzz.to_le_bytes());
                b[16..20].copy_from_slice(&a.flat.to_le_bytes());
                b[20..24].copy_from_slice(&a.res.to_le_bytes());
            }
            uwrite(arg, &b, size.max(24))
        }
        _ => return Some(-(Errno::Enotty.as_i32() as i64)),
    } };
    Some(rv)
}

/// Boot-time creation of the `/dev/input` directory. Event nodes are not
/// fabricated here; `install_device` publishes `/dev/input/event<id>` only
/// after the matching virtio-input device probes, and `remove_device` removes
/// it on teardown.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(depth)
pub fn init() {
    devfs::register_dir("/dev/input");
}

/// Register one model-owned `/dev/input/event<id>` node.
/// # C: O(depth)
pub fn register_node(id: u32) -> bool {
    if (id as usize) >= MAX_EVDEV {
        return false;
    }
    let slot = id as usize;
    if EVDEV_DEVICES.lock()[slot].is_some() {
        return false;
    }
    let factory: drv::NodeFactory = Arc::new(move || make_evdev_inode(id));
    let dev = match drv::try_device_add(Arc::new(
        drv::Device::new("input", alloc::format!("event{id}"), 0, 0, id)
            .with_devnode("input", alloc::format!("input/event{id}"), Some((13, 64 + id)))
            .with_node_factory(factory),
    )) {
        Ok(dev) => dev,
        Err(_) => return false,
    };
    EVDEV_DEVICES.lock()[slot] = Some(dev);
    true
}

/// Remove one model-owned `/dev/input/event<id>` node and clear its
/// notification inode.
/// # C: O(depth)
pub fn unregister_node(id: u32) -> bool {
    if (id as usize) >= MAX_EVDEV {
        return false;
    }
    let slot = id as usize;
    EVDEV_NODES.lock()[slot] = None;
    let dev = EVDEV_DEVICES.lock()[slot].take();
    if let Some(dev) = dev {
        drv::device_del(&dev);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn register_node_is_idempotent_without_republishing() {
        let id = (MAX_EVDEV - 1) as u32;
        let _ = unregister_node(id);

        assert!(register_node(id));
        assert!(!register_node(id));
        assert_eq!(
            drv::devices().iter()
                .filter(|d| d.bus == "input" && d.addr == alloc::format!("event{id}"))
                .count(),
            1
        );

        assert!(unregister_node(id));
    }

    #[test]
    fn register_node_leaves_slot_free_when_model_publication_conflicts() {
        let id = (MAX_EVDEV - 2) as u32;
        let _ = unregister_node(id);
        let addr = alloc::format!("event{id}");
        let conflict = drv::device_add(Arc::new(
            drv::Device::new("input", String::from(addr.as_str()), 0, 0, id)
                .with_devnode("input", alloc::format!("input/event{id}"), Some((13, 64 + id)))));

        assert!(!register_node(id));
        assert!(EVDEV_DEVICES.lock()[id as usize].is_none());
        assert_eq!(
            drv::devices().iter()
                .filter(|d| d.bus == "input" && d.addr == addr)
                .count(),
            1
        );

        drv::device_del(&conflict);
        assert!(register_node(id));
        assert!(unregister_node(id));
    }
}
