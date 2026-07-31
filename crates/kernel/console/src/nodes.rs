// The ONE place a console tty inode is constructed. Every one gets its
// `ConsoleData` here, which is what `crate::identity` resolves against — an
// inode built anywhere else is not a tty as far as the ioctl, ctty and hangup
// paths are concerned, by design.

use alloc::sync::Arc;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, InodeBuilder, InodeRef};

use crate::devnum;
use crate::ids;
use crate::identity::{ConsoleData, TtyBinding};

const CONSOLE_MODE: u16 = 0o666;
const VT_MODE: u16 = 0o620;
const SYSTEM_CONSOLE_MODE: u16 = 0o600;
const SERIAL_CONSOLE_MODE: u16 = 0o660;

/// The tty `file_operations` vectors. Kernel-only: they run the job-control
/// gate and the blocking read path, which live in `tty::jobctl::check` /
/// `sched::live`. A host build constructs the same inodes with the generic
/// vector — identity never consults `f_op`, `i_private` carries it.
#[cfg(target_os = "oxide-kernel")]
fn vt_fops() -> Arc<dyn FileOps> { Arc::new(crate::vt_console::ConsoleFileOps) }
#[cfg(target_os = "oxide-kernel")]
fn system_console_fops() -> Arc<dyn FileOps> { Arc::new(crate::vt_console::SystemConsoleFileOps) }
#[cfg(target_os = "oxide-kernel")]
fn serial_fops() -> Arc<dyn FileOps> { Arc::new(crate::serial::SerialFileOps) }
#[cfg(not(target_os = "oxide-kernel"))]
fn vt_fops() -> Arc<dyn FileOps> { vfs::default_file_ops() }
#[cfg(not(target_os = "oxide-kernel"))]
fn system_console_fops() -> Arc<dyn FileOps> { vfs::default_file_ops() }
#[cfg(not(target_os = "oxide-kernel"))]
fn serial_fops() -> Arc<dyn FileOps> { vfs::default_file_ops() }

/// Shared console tty construction: the number, the device number, and the
/// `ConsoleData` that makes the inode resolvable, all from ONE place.
/// # C: O(1)
fn tty_inode(
    ino: vfs::Ino,
    rdev: u32,
    mode: u16,
    binding: TtyBinding,
    fops: Arc<dyn FileOps>,
) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, mode), default_inode_ops(), fops)
        .fsid(devfs::DEVFS_FSID)
        .rdev(rdev)
        .private(Arc::new(ConsoleData::new(binding)))
        .build()
}

/// Build a VT console inode pinned to `vt`. Use 0 for `/dev/tty0`, the
/// foreground-VT device (Linux `4:0`); 1..=N_VT for the per-VT slots.
/// # C: O(1)
pub fn make_console_inode(vt: u8) -> InodeRef {
    let binding = if vt == 0 { TtyBinding::ForegroundVt } else { TtyBinding::Vt(vt) };
    let mode = if vt == 0 { CONSOLE_MODE } else { VT_MODE };
    tty_inode(ids::vt_ino(vt), devnum::vt_rdev(vt), mode, binding, vt_fops())
}

/// Build the `/dev/tty` controlling-terminal alias (Linux `5:0`). It has a
/// distinct VFS identity from `/dev/tty0` so openat can apply the alias's
/// per-process `ctty` resolution without changing direct `/dev/tty0` opens.
/// # C: O(1)
pub fn make_tty_alias_inode() -> InodeRef {
    tty_inode(ids::tty_ino(ids::TTY_ALIAS_INO_LB), devnum::tty_alias_rdev(),
              CONSOLE_MODE, TtyBinding::ForegroundVt, vt_fops())
}

/// Build the `/dev/console` (preferred-console, 5:1) inode. # C: O(1)
pub fn make_system_console_inode() -> InodeRef {
    tty_inode(ids::tty_ino(ids::SYSTEM_CONSOLE_INO_LB), devnum::system_console_rdev(),
              SYSTEM_CONSOLE_MODE, TtyBinding::PreferredConsole, system_console_fops())
}

/// Build the `/dev/ttyS0` serial tty inode. # C: O(1)
pub fn make_serial_inode() -> InodeRef {
    tty_inode(ids::tty_ino(ids::SERIAL_INO_LB), devnum::serial_rdev(),
              SERIAL_CONSOLE_MODE, TtyBinding::Serial, serial_fops())
}
