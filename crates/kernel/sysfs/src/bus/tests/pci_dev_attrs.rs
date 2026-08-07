//! `/sys/devices/pci0000:00/<addr>` attribute surface.
//!
//! libdrm reports a DRM device only when it can fetch the full PCI identity
//! of the card's parent: it reads `revision`, `vendor`, `device`,
//! `subsystem_vendor` and `subsystem_device`, and falls back to the raw
//! `config` blob when any of them is missing. A directory that omits them
//! makes the counting pass of `drmGetDevices2` accept the device and the
//! fetching pass drop it, which is what crashed callers that size their loop
//! from the first count.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{DirContext, DirEmit, FileType, InodeRef, VfsError};

use super::make_devices_root_inode;


const TEST_VENDOR: u16 = 0x1af4;
const TEST_DEVICE: u16 = 0x1050;
const TEST_SUBSYSTEM_VENDOR: u16 = 0x1af4;
const TEST_SUBSYSTEM_DEVICE: u16 = 0x1100;
const TEST_REVISION: u8 = 0x01;
const TEST_IRQ: u32 = 11;
const TEST_VGA_CLASS: u32 = 0x030000;
const ATTR_BUFFER_BYTES: usize = 64;

fn registered(addr: &str) -> Arc<drv::Device> {
    let dev = Arc::new(
        drv::Device::new("pci", String::from(addr), TEST_VENDOR, TEST_DEVICE, TEST_VGA_CLASS)
            .with_pci_ident(drv::PciIdent {
                revision: TEST_REVISION,
                header_type: pci::uapi::HEADER_TYPE_NORMAL,
                subsystem_vendor: TEST_SUBSYSTEM_VENDOR,
                subsystem_device: TEST_SUBSYSTEM_DEVICE,
                interrupt_line: TEST_IRQ,
                serial_number: None,
            }));
    drv::try_device_add(Arc::clone(&dev)).expect("test pci registration");
    dev
}

/// Collect every entry name a directory emits. # C: O(n)
struct Names(Vec<String>);
impl DirEmit for Names {
    fn emit(&mut self, name: &str, _ino: u64, _d: FileType, _next: u64) -> bool {
        self.0.push(String::from(name));
        true
    }
}

fn entry_names(dir: &InodeRef) -> Vec<String> {
    let mut actor = Names(Vec::new());
    let mut pos = 0u64;
    loop {
        let before = actor.0.len();
        let end = {
            let mut ctx = DirContext::new(pos, &mut actor);
            dir.readdir(&mut ctx).expect("readdir");
            ctx.pos
        };
        if actor.0.len() == before { break; }
        pos = end;
    }
    actor.0
}

fn read_attr(dir: &vfs::InodeRef, name: &str) -> String {
    let attr = dir.lookup(name).unwrap_or_else(|_| panic!("{name} attribute"));
    let mut buf = [0u8; ATTR_BUFFER_BYTES];
    let n = attr.read(0, &mut buf).expect("read attribute");
    String::from_utf8(buf[..n].to_vec()).expect("utf8")
}

#[test]
fn pci_function_publishes_the_identity_attributes_libdrm_fetches() {
    const ADDR: &str = "0000:00:02.0";
    let dev = registered(ADDR);
    let dir = make_devices_root_inode("pci").lookup(ADDR).expect("pci device dir");

    assert_eq!(read_attr(&dir, "vendor"), "0x1af4\n");
    assert_eq!(read_attr(&dir, "device"), "0x1050\n");
    assert_eq!(read_attr(&dir, "subsystem_vendor"), "0x1af4\n");
    assert_eq!(read_attr(&dir, "subsystem_device"), "0x1100\n");
    assert_eq!(read_attr(&dir, "revision"), "0x01\n");
    assert_eq!(read_attr(&dir, "class"), "0x030000\n");
    assert_eq!(read_attr(&dir, "irq"), "11\n");

    drv::device_del(&dev);
}

#[test]
fn config_blob_is_a_whole_config_space_file() {
    const ADDR: &str = "0000:00:02.1";
    let dev = registered(ADDR);
    let dir = make_devices_root_inode("pci").lookup(ADDR).expect("pci device dir");

    let config = dir.lookup("config").expect("config attribute");
    assert_eq!(config.size(), pci::uapi::CFG_SPACE_SIZE as u64);
    assert_eq!(config.i_mode() & 0o777, 0o644);
    assert_eq!(config.file_type(), FileType::Regular);

    drv::device_del(&dev);
}

#[test]
fn attribute_names_appear_in_the_directory_listing() {
    const ADDR: &str = "0000:00:02.2";
    let dev = registered(ADDR);
    let dir = make_devices_root_inode("pci").lookup(ADDR).expect("pci device dir");
    let names = entry_names(&dir);

    for expected in ["config", "revision", "subsystem_vendor", "subsystem_device", "vendor",
                     "device", "class", "irq", "resource", "enable", "local_cpus",
                     "local_cpulist", "numa_node", "modalias", "uevent", "remove", "rescan",
                     "boot_vga", "power_state", "msi_bus", "ari_enabled",
                     "broken_parity_status", "dma_mask_bits", "consistent_dma_mask_bits"] {
        assert!(names.iter().any(|n| n == expected), "missing {expected} in {names:?}");
    }

    drv::device_del(&dev);
}

#[test]
fn a_removed_function_serves_no_attributes() {
    const ADDR: &str = "0000:00:02.3";
    let dev = registered(ADDR);
    let dir = make_devices_root_inode("pci").lookup(ADDR).expect("pci device dir");
    drv::device_del(&dev);

    let mut buf = [0u8; ATTR_BUFFER_BYTES];
    match dir.lookup("revision") {
        Ok(attr) => assert_eq!(attr.read(0, &mut buf), Err(VfsError::Enodev)),
        Err(err) => assert_eq!(err, VfsError::Enoent),
    }
}
