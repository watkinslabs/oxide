use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use sync::{Kernfs as SysfsLockClass, Spinlock};

use vfs::{
    mk_mode, DirContext, File, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps,
    InodeRef, KResult, PollSubscribers, VfsError, POLL_ERR, POLL_IN, POLL_PRI,
};

use crate::{make_body_inode, make_symlink_inode, read_window, uevent_action, DIR_PERM, RO_PERM,
            RW_PERM};

/// Live foreground-VT query (`tty::live::foreground`), wired at boot via
/// `set_active_vt_hook`. `null` (unwired) → VT 1, the boot foreground VT.
/// Held as an erased fn-pointer to keep sysfs free of a `tty` dependency
/// (mirrors `tty::live`'s own `KBD_SINK`/`APP_CURSOR_Q` erased hooks).
static ACTIVE_VT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Generation of the live `tty0/active` value. Linux sysfs wakes pollers with
/// `POLLPRI|POLLERR` when an attribute changes; logind uses this edge to track
/// the foreground VT and activate the matching graphical session.
static ACTIVE_VT_GEN: AtomicU64 = AtomicU64::new(1);

/// Every live `tty0/active` inode's poll queue. Attribute inodes are produced
/// during lookup, so the canonical VT state owns their weak registry.
static ACTIVE_VT_SUBS: Spinlock<Vec<Weak<PollSubscribers>>, SysfsLockClass> =
    Spinlock::new(Vec::new());

/// Default foreground VT reported when no live query is wired. # C: n/a
const DEFAULT_FG_VT: u8 = 1;

/// Wire the live foreground-VT query (boot wiring, once). Pass
/// `tty::live::foreground`. # C: O(1)
pub fn set_active_vt_hook(f: fn() -> u8) {
    ACTIVE_VT_HOOK.store(f as *mut (), Ordering::Release);
}

/// Publish a foreground-VT change to `/sys/class/tty/tty0/active` pollers.
/// The VT owner calls this only after its canonical foreground state changes.
/// # C: O(N_pollers)
pub fn notify_active_vt() {
    let next = ACTIVE_VT_GEN.fetch_add(1, Ordering::AcqRel) + 1;
    #[cfg(not(feature = "debug-displaystack"))]
    let _ = next;
    let wake = {
        let mut g = ACTIVE_VT_SUBS.lock();
        g.retain(|w| w.upgrade().is_some());
        g.iter().filter_map(|w| w.upgrade()).collect::<Vec<_>>()
    };
    #[cfg(feature = "debug-displaystack")]
    {
        klog::write_raw(b"[VT-POLL notify gen=");
        klog::write_dec_u64(next);
        klog::write_raw(b" queues=");
        klog::write_dec_u64(wake.len() as u64);
        klog::write_raw(b"]\n");
    }
    for subs in wake { subs.notify_mask(POLL_PRI | POLL_ERR); }
}

/// Current foreground video VT (1-based). Falls back to `DEFAULT_FG_VT`
/// until the live query is wired. # C: O(1) + query cost
fn active_vt() -> u8 {
    let raw = ACTIVE_VT_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return DEFAULT_FG_VT; }
    // SAFETY: ACTIVE_VT_HOOK is only ever set via set_active_vt_hook with a
    // non-null `fn() -> u8` cast through `as *mut ()`; the reverse transmute
    // restores the identical signature.
    let f: fn() -> u8 = unsafe { core::mem::transmute::<*mut (), fn() -> u8>(raw) };
    f().max(DEFAULT_FG_VT)
}

#[cfg(target_arch = "aarch64")]
const SERIAL_TTY_MAJOR: u32 = 204;
#[cfg(not(target_arch = "aarch64"))]
const SERIAL_TTY_MAJOR: u32 = 4;

const TTY_DEVICES: &[(&str, u32, u32)] = &[
    ("console", 5, 1),
    ("tty",     5, 0),
    ("tty0",    4, 0),
    (cmdline::serial_line_name(), SERIAL_TTY_MAJOR, 64),
    ("ttynull", 240, 0),
];

fn tty_dev(name: &str) -> Option<(u32, u32)> {
    if let Some(dev) = TTY_DEVICES.iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, maj, min)| (*maj, *min)) {
        return Some(dev);
    }

    let number = name.strip_prefix("tty")?;
    if number.is_empty() || (number.len() > 1 && number.starts_with('0')) {
        return None;
    }
    let minor = number.parse::<u32>().ok()?;
    (minor >= 1 && minor <= tty::N_VT as u32).then_some((4, minor))
}

/// Emit the fixed tty aliases/serial line and every numbered VT registered in
/// `/dev`, using the directory's production lookup to resolve each inode.
/// # C: O(N_VT log N_VT)
fn emit_tty_devices(inode: &Inode, ctx: &mut DirContext,
                    file_type: FileType) -> KResult<()> {
    let mut entries = crate::readdir::DirEntries::new(inode);
    for (name, _, _) in TTY_DEVICES { entries.push(name, file_type); }
    for vt in 1..=tty::N_VT {
        let name = alloc::format!("tty{vt}");
        entries.push(&name, file_type);
    }
    entries.emit(ctx)
}

fn emit_tty_uevent(action: &str, name: &str, major: u32, minor: u32) {
    let devpath = alloc::format!("/devices/virtual/tty/{}", name);
    let devname = alloc::format!("DEVNAME={}", name);
    let maj = alloc::format!("MAJOR={}", major);
    let min = alloc::format!("MINOR={}", minor);
    ::netlink::emit_uevent_with_env(action, &devpath, "tty", &[&devname, &maj, &min]);
}

struct SysClassTtyOps;
impl InodeOps for SysClassTtyOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if tty_dev(name).is_none() { return Err(VfsError::Enoent); }
        let mut target = String::from("../../devices/virtual/tty/");
        target.push_str(name);
        Ok(make_symlink_inode(target.into_bytes()))
    }
}
impl FileOps for SysClassTtyOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        emit_tty_devices(inode, ctx, FileType::Symlink)
    }
}

pub(crate) fn make_sys_class_tty_inode() -> InodeRef {
    InodeBuilder::new(crate::ids::TTY_VIRT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassTtyOps), Arc::new(SysClassTtyOps)).build()
}

struct SysDevicesVirtualTtyOps;
impl InodeOps for SysDevicesVirtualTtyOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (major, minor) = tty_dev(name).ok_or(VfsError::Enoent)?;
        Ok(make_tty_device_inode(String::from(name), major, minor))
    }
}
impl FileOps for SysDevicesVirtualTtyOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        emit_tty_devices(inode, ctx, FileType::Directory)
    }
}

pub(crate) fn make_sys_devices_virtual_tty_inode() -> InodeRef {
    InodeBuilder::new(crate::ids::TTY_CLASS, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualTtyOps), Arc::new(SysDevicesVirtualTtyOps)).build()
}

struct TtyDeviceData { name: String, major: u32, minor: u32 }

/// The `active` sysfs attribute exists only on the VT master (`tty0`) and the
/// system console (`console`) — Linux `tty0`/`console` register a
/// `dev_attr_active`; ordinary ttys (`ttyS0`, …) have none. # C: O(1)
fn tty_has_active(name: &str) -> bool {
    name == "tty0" || name == "console"
}

/// Per-device attribute file names, in `iterate` order. # C: O(1)
fn tty_dev_attrs(name: &str) -> &'static [&'static str] {
    if tty_has_active(name) { &["active", "dev", "uevent"] } else { &["dev", "uevent"] }
}

struct TtyDeviceOps;
impl InodeOps for TtyDeviceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<TtyDeviceData>().ok_or(VfsError::Einval)?;
        match name {
            "dev" => {
                let body = alloc::format!("{}:{}\n", d.major, d.minor).into_bytes();
                Ok(make_body_inode(body, crate::ids::TTY_ATTR + d.minor as Ino))
            }
            "uevent" => Ok(make_tty_uevent_inode(d.name.clone(), d.major, d.minor)),
            "subsystem" => Ok(make_symlink_inode(b"../../../../class/tty".to_vec())),
            "active" if tty_has_active(&d.name) =>
                Ok(make_tty_active_inode(&d.name, d.minor)),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for TtyDeviceOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = match inode.private::<TtyDeviceData>() { Some(d) => d, None => return Ok(()) };
        let mut es = crate::readdir::DirEntries::new(inode);
        for name in tty_dev_attrs(&d.name) { es.push(name, FileType::Regular); }
        es.push("subsystem", FileType::Symlink);
        es.emit(ctx)
    }
}

/// `f_op` for `/sys/class/tty/{tty0,console}/active`. `tty0/active` reports the
/// live foreground VT (`ttyN`); `console/active` reports every registered
/// console. Linux serves the `active` attr fresh on each read (VT switches
/// change it), so the body is formatted per-read. # C: O(1)
struct TtyActiveData { is_vt: bool }

/// Device name a registered console is reported under by `console/active`.
///
/// Linux resolves the console through its tty driver and prints the DRIVER's
/// line name, except for `tty0`, which it deliberately leaves unresolved
/// because consumers match on it. The serial line's driver name is the node
/// this kernel publishes — `ttyS0` on both arches, the aarch64 one being the
/// PL011 — so a getty generated from this file opens a path that exists.
/// # C: O(1)
fn console_line_name(k: cmdline::ConsoleKind) -> String {
    match k {
        cmdline::ConsoleKind::Null => String::from("ttynull"),
        cmdline::ConsoleKind::Serial => String::from(cmdline::serial_line_name()),
        cmdline::ConsoleKind::Vt(0) => String::from("tty0"),
        cmdline::ConsoleKind::Vt(n) => alloc::format!("tty{}", n),
    }
}

/// Body of `/sys/class/tty/console/active`: the registered consoles,
/// space-separated, preferred last, one trailing newline. # C: O(consoles)
fn console_active_body() -> Vec<u8> {
    let active = cmdline::active_consoles();
    let mut out = String::new();
    for (i, k) in active.as_slice().iter().enumerate() {
        if i != 0 { out.push(' '); }
        out.push_str(&console_line_name(*k));
    }
    out.push('\n');
    out.into_bytes()
}

struct TtyActiveFileOps;
impl FileOps for TtyActiveFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<TtyActiveData>().ok_or(VfsError::Einval)?;
        let body: Vec<u8> = if d.is_vt {
            alloc::format!("tty{}\n", active_vt()).into_bytes()
        } else {
            console_active_body()
        };
        #[cfg(feature = "debug-displaystack")]
        if d.is_vt && off == 0 {
            klog::write_raw(b"[VT-POLL read ");
            klog::write_raw(&body);
            klog::write_raw(b"]\n");
        }
        Ok(read_window(&body, off, buf))
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let n = self.read(file.inode(), off, buf)?;
        if off == 0 && file.inode().private::<TtyActiveData>().is_some_and(|d| d.is_vt) {
            file.set_private_data(ACTIVE_VT_GEN.load(Ordering::Acquire));
        }
        Ok(n)
    }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
    fn on_open_file(&self, file: &File) -> KResult<()> {
        if file.inode().private::<TtyActiveData>().is_some_and(|d| d.is_vt) {
            file.set_private_data(ACTIVE_VT_GEN.load(Ordering::Acquire));
        }
        Ok(())
    }
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll_open_file(&self, file: &File) -> u32 {
        let Some(d) = file.inode().private::<TtyActiveData>() else { return POLL_IN; };
        if !d.is_vt { return POLL_IN; }
        let cur = ACTIVE_VT_GEN.load(Ordering::Acquire);
        if cur != file.private_data() { POLL_IN | POLL_PRI | POLL_ERR } else { POLL_IN }
    }
}

/// Build the read-only `active` attribute inode for `tty0`/`console`. # C: O(1)
fn make_tty_active_inode(name: &str, minor: u32) -> InodeRef {
    let is_vt = name == "tty0";
    let subs = Arc::new(PollSubscribers::new());
    if is_vt {
        let mut g = ACTIVE_VT_SUBS.lock();
        g.retain(|w| w.upgrade().is_some());
        g.push(Arc::downgrade(&subs));
    }
    InodeBuilder::new(crate::ids::TTY_RO_ATTR + minor as Ino, mk_mode(FileType::Regular, RO_PERM),
        crate::kobject::attr_inode_ops(), Arc::new(TtyActiveFileOps))
        .private(Arc::new(TtyActiveData { is_vt }))
        .poll_subs_arc(subs)
        .build()
}

#[cfg(test)]
mod tests;

fn make_tty_device_inode(name: String, major: u32, minor: u32) -> InodeRef {
    InodeBuilder::new(crate::ids::TTY_DIR + minor as Ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(TtyDeviceOps), Arc::new(TtyDeviceOps))
        .private(Arc::new(TtyDeviceData { name, major, minor }))
        .build()
}

struct TtyUeventData { name: String, major: u32, minor: u32 }

struct TtyUeventFileOps;
impl FileOps for TtyUeventFileOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<TtyUeventData>().ok_or(VfsError::Einval)?;
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME={}\n", d.major, d.minor, d.name).into_bytes();
        Ok(read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<TtyUeventData>().ok_or(VfsError::Einval)?;
        emit_tty_uevent(uevent_action(b), &d.name, d.major, d.minor);
        Ok(b.len())
    }
}

fn make_tty_uevent_inode(name: String, major: u32, minor: u32) -> InodeRef {
    InodeBuilder::new(crate::ids::TTY_RW_ATTR + minor as Ino, mk_mode(FileType::Regular, RW_PERM),
        crate::kobject::attr_inode_ops(), Arc::new(TtyUeventFileOps))
        .private(Arc::new(TtyUeventData { name, major, minor }))
        .build()
}
