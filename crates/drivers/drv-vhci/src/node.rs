//! The character-device file operations.
//!
//! One device per open description, so two processes each get their own
//! controller rather than fighting over one. Everything the operations decide
//! lives in `protocol`; this module only moves bytes and holds the description
//! alive.

extern crate alloc;
use alloc::sync::Arc;

use bluetooth::hci::registry;
use bluetooth::hci::transport::HciTransport;
use syscall::errno::Errno;
use vfs::{FileOps, Inode, InodeRef, KResult, VfsError};

use crate::device::VhciDevice;
use crate::protocol::{parse_write, WriteAction};

/// Character-device major and minor for the node. The pair is fixed because the
/// node is created by name at boot and a tool opens it by path.
pub const VHCI_MAJOR: u32 = 10;
pub const VHCI_MINOR: u32 = 137;

fn errno_to_vfs(e: Errno) -> VfsError {
    match e {
        Errno::Einval => VfsError::Einval,
        Errno::Enodev => VfsError::Enodev,
        Errno::Ebadf  => VfsError::Ebadf,
        Errno::Enfile => VfsError::Emfile,
        _ => VfsError::Eio,
    }
}

/// File operations for the node. The device itself hangs off the inode's
/// private slot, which is what ties one description to one controller.
pub struct VhciFileOps;

fn device_of(inode: &Inode) -> KResult<&VhciDevice> {
    inode.private::<VhciDevice>().ok_or(VfsError::Einval)
}

impl FileOps for VhciFileOps {
    /// A read hands the process the next frame the stack sent the controller.
    /// A frame longer than the buffer is NOT split: the protocol is
    /// frame-oriented, and half a frame would desynchronise the reader
    /// permanently. # C: O(len)
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let dev = device_of(inode)?;
        let Some(frame) = dev.read_frame() else { return Err(VfsError::Eagain); };
        if frame.len() > buf.len() { return Err(VfsError::Einval); }
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }

    /// A write is either traffic the controller is reporting, or the request
    /// that creates the controller in the first place. # C: O(len)
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let dev = device_of(inode)?;
        match parse_write(buf, dev.has_device()).map_err(errno_to_vfs)? {
            WriteAction::Frame(frame) => {
                let index = dev.index().ok_or(VfsError::Enodev)?;
                let hdev = registry::by_index(index).ok_or(VfsError::Enodev)?;
                bluetooth::hci::rx::receive(&hdev, &frame, 0);
                Ok(buf.len())
            }
            WriteAction::Create(flags) => {
                let owner: Arc<VhciDevice> = inode.i_private().clone()
                    .downcast::<VhciDevice>().map_err(|_| VfsError::Einval)?;
                let transport: Arc<dyn HciTransport> = owner;
                let hdev = registry::register(transport).map_err(errno_to_vfs)?;
                dev.attach(flags, hdev.index);
                Ok(buf.len())
            }
        }
    }

    /// # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let readable = inode.private::<VhciDevice>().is_some_and(|d| d.readable());
        if readable { vfs::POLL_IN | vfs::POLL_OUT } else { vfs::POLL_OUT }
    }
}

/// Build the inode for one open of the node. Each open gets its own device, so
/// two processes each present their own controller. # C: O(1)
pub fn make_vhci_inode(ino: vfs::Ino) -> InodeRef {
    vfs::InodeBuilder::new(
        ino,
        vfs::mk_mode(vfs::FileType::CharDev, 0o600),
        vfs::default_inode_ops(),
        Arc::new(VhciFileOps),
    )
    .private(Arc::new(VhciDevice::new()))
    .rdev(((VHCI_MAJOR) << 8) | VHCI_MINOR)
    .build()
}

/// Inode number for the node, from the range reserved for driver-published
/// pseudo devices.
pub const INO_VHCI: vfs::Ino = 0x2000_0040;

/// Publish `/dev/vhci`. Called once at boot: the node must exist before any
/// process can present a controller, and nothing else creates it. # C: O(1)
pub fn register() -> Result<(), drv::Error> {
    let dev = Arc::new(
        drv::Device::new("misc", alloc::string::String::from("vhci"), 0, 0, 0)
            .with_devnode("misc", alloc::string::String::from("vhci"),
                Some((VHCI_MAJOR, VHCI_MINOR)))
            .with_node_factory(Arc::new(|| make_vhci_inode(INO_VHCI))),
    );
    drv::try_device_add(dev).map(|_| ())
}
