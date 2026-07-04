// /dev/input/event<id> evdev substrate per `35§R01`. Full Linux evdev ABI:
// blocking/non-blocking reads of 24-byte `input_event` records, `->poll`
// (POLLIN only when a record is queued), per-fd poll/epoll subscribers, and
// the EVIOCG* identification/capability ioctls answered from the device's
// real virtio config-space capability bitmaps (drv::VirtioInputDev).

use alloc::sync::Arc;
use vfs::{File, FileType, Ino, Inode, InodeRef, KResult, VfsError, POLL_IN, POLL_OUT,
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
/// `drv::try_device_add` / `drv::device_del` through the devtmpfs hook.
static EVDEV_DEVICES: Spinlock<[Option<Arc<drv::Device>>; MAX_EVDEV], NodesLockClass>
    = Spinlock::new([const { None }; MAX_EVDEV]);

/// `EVIOCGRAB` owner per evdev id. Value is the open `File` address; zero means
/// ungrabbed. Linux evdev grabs are per open file description, not per inode.
static EVDEV_GRABS: Spinlock<[usize; MAX_EVDEV], NodesLockClass> =
    Spinlock::new([0; MAX_EVDEV]);

const EVDEV_FILE_REVOKED: u64 = 1 << 0;

fn file_token(file: &File) -> usize {
    file as *const File as usize
}

fn evdev_id(inode: &Inode) -> Option<u32> {
    inode.private::<EvdevData>().map(|d| d.id)
}

fn grabbed_by_other(id: u32, token: usize) -> bool {
    let owner = EVDEV_GRABS.lock()[(id as usize).min(MAX_EVDEV - 1)];
    owner != 0 && owner != token
}

fn release_grab(id: u32, token: usize) {
    let slot = (id as usize).min(MAX_EVDEV - 1);
    let mut grabs = EVDEV_GRABS.lock();
    if grabs[slot] == token {
        grabs[slot] = 0;
        crate::evdev_queue::queue(id).waiters.wake_one();
        notify_evdev_subs(id);
    }
}

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
        let id = match evdev_id(inode) { Some(id) => id, None => return Ok(0) };
        if buf.len() < INPUT_EVENT_BYTES { return Ok(0); }
        // SAFETY: caller is the running task on this CPU; read_blocking parks safely via WaitList and reschedules.
        let n = unsafe { crate::evdev_queue::queue(id).read_blocking(buf) };
        Ok(n)
    }

    fn read_file(&self, file: &File, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match evdev_id(file.inode()) { Some(id) => id, None => return Ok(0) };
        if file.private_data() & EVDEV_FILE_REVOKED != 0 { return Err(VfsError::Enodev); }
        if buf.len() < INPUT_EVENT_BYTES { return Ok(0); }
        let token = file_token(file);
        loop {
            if !grabbed_by_other(id, token) {
                // SAFETY: caller is the running task on this CPU; read_blocking parks safely via WaitList and reschedules.
                return Ok(unsafe { crate::evdev_queue::queue(id).read_blocking(buf) });
            }
            // SAFETY: caller is running task; preempt-off; same wait discipline
            // as `EvdevQueue::read_blocking`, but waiting for grab release.
            unsafe { crate::evdev_queue::queue(id).waiters.park(); }
            #[cfg(target_os = "oxide-kernel")]
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(test)]
            return Err(VfsError::Eagain);
        }
    }

    /// Non-blocking variant per O_NONBLOCK.
    fn read_nonblock(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match evdev_id(inode) { Some(id) => id, None => return Ok(0) };
        if buf.len() < INPUT_EVENT_BYTES { return Ok(0); }
        match crate::evdev_queue::queue(id).try_pop_bytes(buf) {
            Some(n) => Ok(n),
            None    => Err(VfsError::Eagain),
        }
    }

    fn read_nonblock_file(&self, file: &File, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::INPUT_EVENT_BYTES;
        let id = match evdev_id(file.inode()) { Some(id) => id, None => return Ok(0) };
        if file.private_data() & EVDEV_FILE_REVOKED != 0 { return Err(VfsError::Enodev); }
        if buf.len() < INPUT_EVENT_BYTES { return Ok(0); }
        if grabbed_by_other(id, file_token(file)) { return Err(VfsError::Eagain); }
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
        let id = match evdev_id(inode) { Some(id) => id, None => return POLL_OUT };
        if crate::evdev_queue::queue(id).is_empty() { POLL_OUT }
        else { POLL_IN | POLL_OUT }
    }

    fn poll_open_file(&self, file: &File) -> u32 {
        if file.private_data() & EVDEV_FILE_REVOKED != 0 { return POLL_OUT | vfs::POLL_HUP; }
        let id = match evdev_id(file.inode()) { Some(id) => id, None => return POLL_OUT };
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
#[inline] fn ioc_dir(req: u64)  -> u32 { ((req >> 30) & 0x3) as u32 }

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

fn err(errno: syscall::errno::Errno) -> i64 {
    -(errno.as_i32() as i64)
}

fn valid_user_range(arg: u64, bytes: u64) -> bool {
    arg != 0
        && arg < hal::USER_VA_END
        && arg
            .checked_add(bytes)
            .is_some_and(|end| end <= hal::USER_VA_END)
}

/// Read one Linux `int` from an ioctl user pointer.
/// # SAFETY: `arg..arg+4` was validated as a user range by the caller.
unsafe fn uread_i32(arg: u64) -> i32 {
    let mut b = [0u8; 4];
    for (i, slot) in b.iter_mut().enumerate() {
        // SAFETY: per fn contract; each byte lies inside the validated range.
        *slot = unsafe { core::ptr::read_volatile((arg + i as u64) as *const u8) };
    }
    i32::from_le_bytes(b)
}

/// Read one Linux `unsigned int` from an ioctl user pointer.
/// # SAFETY: `arg..arg+4` was validated as a user range by the caller.
unsafe fn uread_u32(arg: u64) -> u32 {
    let mut b = [0u8; 4];
    for (i, slot) in b.iter_mut().enumerate() {
        // SAFETY: per fn contract; each byte lies inside the validated range.
        *slot = unsafe { core::ptr::read_volatile((arg + i as u64) as *const u8) };
    }
    u32::from_le_bytes(b)
}

/// EVIOC* ioctl handler. Returns `Some(rv)` when the request is recognised;
/// `None` to let the generic CharDev path run. Answers identification +
/// capability queries from the device's real virtio config-space record.
/// # C: O(1)
pub fn handle_evdev_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    let inode: &InodeRef = file.inode();
    let ino = inode.ino();
    if (ino & !0xFF) != EVDEV_INO_BASE || (ino & 0xFF) == 0 { return None; }
    use syscall::errno::Errno;
    if ioc_type(req) != b'E' as u64 as u32 { return None; }
    let nr = ioc_nr(req);

    const EVIOCGRAB_NR:     u32 = 0x90;
    const EVIOCREVOKE_NR:   u32 = 0x91;
    const EVIOCSCLOCKID_NR: u32 = 0xa0;
    const CLOCK_MONOTONIC:  i32 = 1;
    const IOC_WRITE:        u32 = 1;
    const IOC_READ:         u32 = 2;
    if nr == EVIOCSCLOCKID_NR {
        if !valid_user_range(arg, 4) {
            return Some(err(Errno::Efault));
        }
        // SAFETY: `arg..arg+4` was validated above.
        let clock_id = unsafe { uread_i32(arg) };
        return Some(if clock_id == CLOCK_MONOTONIC {
            0
        } else {
            err(Errno::Einval)
        });
    }
    let evdev_id = ((ino & 0xFF) - 1) as u32;
    if nr == crate::EVIOCREP_NR as u32 {
        if !valid_user_range(arg, 8) {
            return Some(err(Errno::Efault));
        }
        match ioc_dir(req) {
            IOC_READ => {
                let repeat = crate::repeat(evdev_id).unwrap_or(crate::DEFAULT_REPEAT);
                let mut b = [0u8; 8];
                b[0..4].copy_from_slice(&repeat[0].to_le_bytes());
                b[4..8].copy_from_slice(&repeat[1].to_le_bytes());
                // SAFETY: `arg..arg+8` was validated above.
                return Some(unsafe { uwrite(arg, &b, 8) });
            }
            IOC_WRITE => {
                // SAFETY: both words lie inside the validated `arg..arg+8`.
                let delay = unsafe { uread_u32(arg) };
                let period = unsafe { uread_u32(arg + 4) };
                if !crate::set_repeat(evdev_id, [delay, period]) {
                    return Some(err(Errno::Enodev));
                }
                return Some(0);
            }
            _ => return Some(err(Errno::Enotty)),
        }
    }
    if nr == EVIOCGRAB_NR {
        let token = file_token(file);
        let slot = (evdev_id as usize).min(MAX_EVDEV - 1);
        if arg != 0 {
            let mut grabs = EVDEV_GRABS.lock();
            return Some(if grabs[slot] == 0 || grabs[slot] == token {
                grabs[slot] = token;
                0
            } else {
                err(Errno::Ebusy)
            });
        }
        release_grab(evdev_id, token);
        return Some(0);
    }
    if nr == EVIOCREVOKE_NR {
        if arg != 0 {
            file.set_private_data(file.private_data() | EVDEV_FILE_REVOKED);
            release_grab(evdev_id, file_token(file));
        }
        return Some(0);
    }

    if !valid_user_range(arg, 1) {
        return Some(err(Errno::Efault));
    }
    let size = ioc_size(req);
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
        _ => return Some(err(Errno::Enotty)),
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
    EVDEV_GRABS.lock()[slot] = 0;
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
    use vfs::{Dentry, OpenFlags};

    fn test_file(id: u32) -> Arc<File> {
        let inode = make_evdev_inode(id);
        File::new(
            inode.clone(),
            Dentry::new_anon(inode),
            OpenFlags::O_RDONLY | OpenFlags::O_NONBLOCK,
        )
    }

    fn test_dev(id: u32) -> crate::VirtioInputDev {
        crate::VirtioInputDev {
            device_key: virtio::VirtioChildDeviceKey::from_raw(0x7000_0000 + id),
            evdev_id: id,
            is_pointer: false,
            name: [0; 128],
            name_len: 0,
            serial: [0; 128],
            serial_len: 0,
            ids: crate::VirtioInputDevIds::default(),
            ev_bits: [0; 32],
            key_bits: crate::CapBitmap::default(),
            rel_bits: crate::CapBitmap::default(),
            abs_bits: crate::CapBitmap::default(),
            led_bits: crate::CapBitmap::default(),
            abs_info: [None; 64],
            prop_bits: [0; 4],
            repeat: crate::DEFAULT_REPEAT,
        }
    }

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
    fn unregister_then_register_restores_model_owned_event_node() {
        let id = (MAX_EVDEV - 3) as u32;
        let addr = alloc::format!("event{id}");
        let _ = unregister_node(id);

        assert!(register_node(id));
        assert!(EVDEV_DEVICES.lock()[id as usize].is_some());
        assert_eq!(
            drv::devices().iter()
                .filter(|d| d.bus == "input" && d.addr == addr)
                .count(),
            1
        );
        assert!(unregister_node(id));
        assert!(EVDEV_DEVICES.lock()[id as usize].is_none());
        assert_eq!(
            drv::devices().iter()
                .filter(|d| d.bus == "input" && d.addr == addr)
                .count(),
            0
        );

        assert!(register_node(id));
        assert!(EVDEV_DEVICES.lock()[id as usize].is_some());
        assert_eq!(
            drv::devices().iter()
                .filter(|d| d.bus == "input" && d.addr == addr)
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
        let conflict = drv::try_device_add(Arc::new(
            drv::Device::new("input", String::from(addr.as_str()), 0, 0, id)
                .with_devnode("input", alloc::format!("input/event{id}"), Some((13, 64 + id)))))
            .expect("conflict device registration");

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

    #[test]
    fn evdev_clockid_ioctl_accepts_only_monotonic_clock() {
        let file = test_file(0);
        let mut monotonic = 1i32;
        let mut realtime = 0i32;
        assert_eq!(
            handle_evdev_ioctl(&file, 0x400445a0, (&mut monotonic as *mut i32) as u64),
            Some(0)
        );
        assert_eq!(
            handle_evdev_ioctl(&file, 0x400445a0, (&mut realtime as *mut i32) as u64),
            Some(-(syscall::errno::Errno::Einval.as_i32() as i64))
        );
        assert_eq!(
            handle_evdev_ioctl(&file, 0x400445a0, 0),
            Some(-(syscall::errno::Errno::Efault.as_i32() as i64))
        );
    }

    #[test]
    fn evdev_repeat_ioctl_round_trips_real_device_state() {
        let id = 4;
        let key = virtio::VirtioChildDeviceKey::from_raw(0x7000_0000 + id);
        let _ = crate::remove_device(key);
        crate::install(test_dev(id));
        let file = test_file(id);
        let mut repeat = [300u32, 45u32];

        assert_eq!(
            handle_evdev_ioctl(&file, crate::EVIOCSREP, repeat.as_mut_ptr() as u64),
            Some(0)
        );
        repeat = [0, 0];
        assert_eq!(
            handle_evdev_ioctl(&file, crate::EVIOCGREP, repeat.as_mut_ptr() as u64),
            Some(8)
        );
        assert_eq!(repeat, [300, 45]);
        assert_eq!(
            handle_evdev_ioctl(&file, crate::EVIOCSREP, 0),
            Some(-(syscall::errno::Errno::Efault.as_i32() as i64))
        );

        assert_eq!(crate::remove_device(key), Some(id));
    }

    #[test]
    fn evdev_grab_is_per_open_file_description() {
        let owner = test_file(1);
        let other = test_file(1);

        assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 1), Some(0));
        assert_eq!(
            handle_evdev_ioctl(&other, crate::EVIOCGRAB, 1),
            Some(-(syscall::errno::Errno::Ebusy.as_i32() as i64))
        );

        crate::evdev_queue::push_event(1, crate::EV_KEY, 30, 1);
        assert_eq!(owner.poll() & POLL_IN, POLL_IN);
        assert_eq!(other.poll() & POLL_IN, 0);

        let mut buf = [0u8; crate::evdev_queue::INPUT_EVENT_BYTES];
        assert_eq!(other.read(&mut buf).err(), Some(VfsError::Eagain));
        assert_eq!(owner.read(&mut buf).unwrap(), buf.len());

        assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 0), Some(0));
        assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 1), Some(0));
        assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 0), Some(0));
    }

    #[test]
    fn evdev_grab_is_released_on_last_close() {
        let owner = test_file(2);
        let other = test_file(2);
        assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 1), Some(0));
        drop(owner);
        assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 1), Some(0));
        assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 0), Some(0));
    }

    #[test]
    fn evdev_revoke_disables_current_open_file() {
        let file = test_file(3);
        assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCREVOKE, 1), Some(0));
        assert_eq!(file.poll() & vfs::POLL_HUP, vfs::POLL_HUP);
        let mut buf = [0u8; crate::evdev_queue::INPUT_EVENT_BYTES];
        assert_eq!(file.read(&mut buf).err(), Some(VfsError::Enodev));
    }
}
