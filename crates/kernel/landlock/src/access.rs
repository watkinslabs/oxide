// What each operation asks for, and what an open records for later.
//
// Read, write and execute are decided once, at open. Truncation and device
// control are decided there too, and the verdict is stored on the open file:
// an fd passed to another process keeps the rights it was opened with, and a
// policy installed after the open cannot retroactively revoke them. That is
// why `ftruncate` and `ioctl` consult the recorded mask rather than re-walking.

extern crate alloc;

use syscall::errno::Errno;
use vfs::{FileType, VfsPath};

use crate::domain::Domain;
use crate::audit::RequestType;
use crate::eval::LayerMasks;
use crate::uapi::*;

/// Rights decided at open but exercised later on the open file.
pub const OPTIONAL_ACCESS: AccessMask = ACCESS_FS_TRUNCATE | ACCESS_FS_IOCTL_DEV;

/// Rights an open must be granted outright. A directory can only be read, so a
/// readable directory open asks for the directory-listing right rather than the
/// file-reading one — conflating them lets a policy that forbids listing be
/// bypassed by opening the directory.
/// # C: O(1)
pub fn open_access(readable: bool, writable: bool, exec: bool, is_dir: bool) -> AccessMask {
    let mut a = 0;
    if readable { if is_dir { return ACCESS_FS_READ_DIR | if writable { ACCESS_FS_WRITE_FILE } else { 0 }; }
                  a |= ACCESS_FS_READ_FILE; }
    if writable { a |= ACCESS_FS_WRITE_FILE; }
    if exec     { a |= ACCESS_FS_EXECUTE; }
    a
}

/// Whether a file type is controlled by device ioctls.
/// # C: O(1)
pub fn is_device(ft: FileType) -> bool {
    matches!(ft, FileType::CharDev | FileType::BlockDev)
}

/// The full mask an open file may be recorded with, unrestricted.
pub const ALL_ACCESS: AccessMask = MASK_ACCESS_FS;

/// Decide an open. Returns the rights to record on the resulting file, or
/// `Eacces` when the rights the open itself needs are not all granted. The
/// recorded mask may be narrower than requested: optional rights that were
/// denied simply do not get recorded, which is what later forbids `ftruncate`
/// on a file opened without the truncation right.
/// # C: O(depth × N_layers × N_rules)
pub fn open_decide(dom: &Domain, path: &VfsPath, open_req: AccessMask, is_device: bool)
    -> Result<AccessMask, Errno>
{
    let mut optional = ACCESS_FS_TRUNCATE;
    if is_device { optional |= ACCESS_FS_IOCTL_DEV; }
    let full = open_req | optional;

    let masks = dom.fs_masks();
    let (mut m, req) = LayerMasks::init(&masks, full);
    if req == 0 { return Ok(full); }
    let chain = crate::walk::ancestors(path);
    let mut satisfied = false;
    for n in chain.iter() {
        if m.unmask(&dom.granted_at(n)) { satisfied = true; break; }
    }
    let allowed = if satisfied {
        full
    } else {
        let mut a = full;
        for l in m.layers.iter() { a &= !*l; }
        a
    };
    if (open_req | allowed) != allowed {
        // Only the rights the OPEN itself needed are reported: the optional
        // ones were asked for speculatively and their absence is recorded on
        // the description rather than refused, so naming them here would
        // describe a denial that did not happen.
        dom.report_denial_masks(&m, RequestType::FsAccess, open_req);
        return Err(Errno::Eacces);
    }
    Ok(allowed)
}

/// Whether an already-open file may be truncated, given the mask recorded at
/// its open.
/// # C: O(1)
pub fn truncate_allowed(recorded: AccessMask) -> bool {
    (recorded & ACCESS_FS_TRUNCATE) != 0
}

/// Whether an ioctl may run on an already-open file. Only device control is
/// gated, and a fixed set of commands stays available regardless: they either
/// act on the filesystem rather than the device, or duplicate an operation that
/// is reachable through `fcntl` anyway, so gating them would restrict nothing.
/// # C: O(1)
pub fn ioctl_allowed(recorded: AccessMask, is_device: bool, cmd: u64) -> bool {
    if (recorded & ACCESS_FS_IOCTL_DEV) != 0 { return true; }
    if !is_device { return true; }
    masked_device_ioctl(cmd)
}

/// Commands exempt from the device-control right.
/// # C: O(1)
pub fn masked_device_ioctl(cmd: u64) -> bool {
    matches!(cmd,
        ioctl::FIOCLEX | ioctl::FIONCLEX | ioctl::FIONBIO | ioctl::FIOASYNC
        | ioctl::FIOQSIZE
        | ioctl::FIFREEZE | ioctl::FITHAW
        | ioctl::FS_IOC_FIEMAP | ioctl::FIGETBSZ
        | ioctl::FICLONE | ioctl::FICLONERANGE | ioctl::FIDEDUPERANGE
        | ioctl::FS_IOC_GETFSUUID | ioctl::FS_IOC_GETFSSYSFSPATH)
}

/// Command numbers the device-control right does not cover.
pub mod ioctl {
    pub const FIONBIO:   u64 = 0x5421;
    pub const FIONCLEX:  u64 = 0x5450;
    pub const FIOCLEX:   u64 = 0x5451;
    pub const FIOASYNC:  u64 = 0x5452;
    pub const FIOQSIZE:  u64 = 0x5460;
    pub const FIGETBSZ:  u64 = 0x2;
    pub const FIFREEZE:  u64 = 0xC004_5877;
    pub const FITHAW:    u64 = 0xC004_5878;
    pub const FS_IOC_FIEMAP: u64 = 0xC020_660B;
    pub const FICLONE:       u64 = 0x4004_9409;
    pub const FICLONERANGE:  u64 = 0x4020_940D;
    pub const FIDEDUPERANGE: u64 = 0xC018_9436;
    pub const FS_IOC_GETFSUUID:      u64 = 0x8011_1500;
    pub const FS_IOC_GETFSSYSFSPATH: u64 = 0x8081_1501;
}

#[cfg(test)]
#[path = "tests/access.rs"]
mod tests;
