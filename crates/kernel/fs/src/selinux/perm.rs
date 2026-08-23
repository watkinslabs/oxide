// The inode permission check the VFS calls, and its installation.

use selinux_runtime::inode::inode_permission_av;

use vfs::{InodeRef, KResult, VfsError};

// Linux's CONFIG_LSM_MMAP_MIN_ADDR default for the x86/64 configuration used
// by this kernel. This is the LSM floor, distinct from the writable
// `vm.mmap_min_addr` DAC floor.
const LSM_MMAP_MIN_ADDR: u64 = 65_536;

/// Label-based permission over one inode. # C: O(1) cached
///
/// Allows when the module has no policy, when the request asks for no
/// permission at all, and when the object has no resolvable label — none of
/// those is a decision the policy has made, and turning any of them into a
/// refusal would refuse work the policy permits.
pub fn inode_permission(inode: &InodeRef, mask: u32) -> KResult<()> {
    if !selinux_runtime::active() { return Ok(()); }
    let Some(isid) = super::label::inode_sid(inode) else { return Ok(()) };
    let Some((_, av)) = inode_permission_av(inode.i_mode() as u32, mask) else { return Ok(()) };
    let Some(class) = super::label::inode_security_class(inode) else { return Ok(()) };
    let ssid = selinux_runtime::task::current_sid();
    selinux_runtime::check::has_perm(ssid, isid, class, av).map_err(|_| VfsError::Eacces)
}

/// Linux `security_mmap_file`: mapping is a distinct file permission, not a
/// read/write pathname check. Executable mappings additionally need execute.
pub fn mmap_file(inode: &InodeRef, shared_write: bool, executable: bool) -> KResult<()> {
    if !selinux_runtime::active() { return Ok(()) }
    let Some(isid) = super::label::inode_sid(inode) else { return Ok(()) };
    let Some(class) = super::label::inode_security_class(inode) else { return Ok(()) };
    let map = selinux::uapi::classmap::perm_bit(class, "map").unwrap_or(0);
    let read = selinux::uapi::classmap::perm_bit(class, "read").unwrap_or(0);
    let write = if shared_write { selinux::uapi::classmap::perm_bit(class, "write").unwrap_or(0) } else { 0 };
    let execute = if executable { selinux::uapi::classmap::perm_bit(class, "execute").unwrap_or(0) } else { 0 };
    selinux_runtime::check::has_perm(selinux_runtime::task::current_sid(), isid, class,
        map | read | write | execute).map_err(|_| VfsError::Eacces)
}

pub fn mprotect_file(inode: &InodeRef, shared_write: bool, executable: bool, execmod: bool) -> KResult<()> {
    if !selinux_runtime::active() { return Ok(()) }
    let Some(isid) = super::label::inode_sid(inode) else { return Ok(()) };
    let Some(class) = super::label::inode_security_class(inode) else { return Ok(()) };
    let read = selinux::uapi::classmap::perm_bit(class, "read").unwrap_or(0);
    let write = if shared_write { selinux::uapi::classmap::perm_bit(class, "write").unwrap_or(0) } else { 0 };
    let execute = if executable { selinux::uapi::classmap::perm_bit(class, "execute").unwrap_or(0) } else { 0 };
    let execmod = if execmod { selinux::uapi::classmap::perm_bit(class, "execmod").unwrap_or(0) } else { 0 };
    selinux_runtime::check::has_perm(selinux_runtime::task::current_sid(), isid, class,
        read | write | execute | execmod).map_err(|_| VfsError::Eacces)
}

fn file_permission(inode: &InodeRef, permission: &'static str) -> KResult<()> {
    if !selinux_runtime::active() { return Ok(()) }
    let Some(isid) = super::label::inode_sid(inode) else { return Ok(()) };
    let Some(class) = super::label::inode_security_class(inode) else { return Ok(()) };
    let Some(bit) = selinux::uapi::classmap::perm_bit(class, permission) else { return Ok(()) };
    selinux_runtime::check::has_perm(selinux_runtime::task::current_sid(), isid, class, bit)
        .map_err(|_| VfsError::Eacces)
}

pub fn file_ioctl(inode: &InodeRef, cmd: u32) -> KResult<()> {
    // These command values are the stable UAPI values used by Linux's
    // selinux_file_ioctl() dispatch. They intentionally select the object
    // permission that the command actually exercises before the generic
    // ioctl permission is considered.
    const FIONREAD: u32 = 0x541B;
    const FIBMAP: u32 = 0x0001;
    const FIGETBSZ: u32 = 0x0002;
    const FIONBIO: u32 = 0x5421;
    const FIOASYNC: u32 = 0x5452;
    const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
    const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
    const FS_IOC_GETVERSION: u32 = 0x8008_7601;
    const FS_IOC_SETVERSION: u32 = 0x4008_7602;

    match cmd {
        FIONREAD | FIBMAP | FIGETBSZ | FS_IOC_GETFLAGS | FS_IOC_GETVERSION =>
            file_permission(inode, "getattr"),
        FS_IOC_SETFLAGS | FS_IOC_SETVERSION => file_permission(inode, "setattr"),
        // Linux's hook passes zero here: sys_ioctl() owns the actual
        // FIONBIO/FIOASYNC state transition.
        FIONBIO | FIOASYNC => Ok(()),
        _ => file_permission(inode, "ioctl"),
    }
}

/// Linux `selinux_mount`: mounting requires `file:mounton` on the target
/// mountpoint, while remount and unmount target the filesystem object.
pub fn mount_on(inode: &InodeRef) -> KResult<()> {
    if !selinux_runtime::active() { return Ok(()) }
    let Some(isid) = super::label::inode_sid(inode) else { return Ok(()) };
    let Some(class) = super::label::inode_security_class(inode) else { return Ok(()) };
    let Some(permission) = selinux::uapi::classmap::perm_bit(class, "mounton") else { return Ok(()) };
    selinux_runtime::check::has_perm(selinux_runtime::task::current_sid(), isid, class, permission)
        .map_err(|_| VfsError::Eacces)
}

pub fn superblock_permission(sb: &vfs::SuperBlock, permission: &'static str) -> KResult<()> {
    if !selinux_runtime::active() { return Ok(()) }
    let Some(security) = sb.security_as::<selinux_runtime::inode::SuperblockSecurity>() else { return Ok(()) };
    let Some(class) = selinux::uapi::classmap::class_by_name("filesystem") else { return Ok(()) };
    let Some(bit) = selinux::uapi::classmap::perm_bit(class, permission) else { return Ok(()) };
    selinux_runtime::check::has_perm(selinux_runtime::task::current_sid(), security.sb_sid, class, bit)
        .map_err(|_| VfsError::Eacces)
}

pub fn mmap_addr(addr: u64) -> bool {
    if !selinux_runtime::active() { return true; }
    let Some(class) = selinux::uapi::classmap::class_by_name("memprotect") else { return true; };
    let Some(bit) = selinux::uapi::classmap::perm_bit(class, "mmap_zero") else { return true; };
    if addr >= LSM_MMAP_MIN_ADDR { return true; }
    selinux_runtime::check::has_perm(selinux_runtime::task::current_sid(),
        selinux_runtime::task::current_sid(), class, bit).is_ok()
}

/// Install the check into the VFS permission path. # C: O(1)
pub fn install() {
    vmm::set_mmap_addr_hook(mmap_addr);
    security::lsm::register_inode_permission(inode_permission);
    security::lsm::register_file_ioctl(file_ioctl);
    security::lsm::register_inode_create(label_created);
    security::lsm::register_inode_instantiate(super::label::label_instantiated);
    security::lsm::register_inode_init_security_anon(super::label::inode_init_security_anon);
    vfs::set_inode_mac_hook(security::lsm::inode_permission);
    vfs::set_inode_create_hook(security::lsm::inode_created);
    vfs::set_inode_instantiated_hook(security::lsm::inode_instantiated);
    vfs::set_inode_init_security_anon_hook(security::lsm::inode_init_security_anon);
}

fn label_created(dir: &InodeRef, inode: &InodeRef, name: &str) {
    let _ = super::label::label_new_inode(dir, inode, name);
}
