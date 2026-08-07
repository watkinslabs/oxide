// The `config` binary attribute: raw config space, served at byte
// granularity. libdrm reads it whenever the identity attributes are absent,
// and lspci/setpci drive it directly.
//
// The window a reader observes depends on its capability, not on the file
// mode: an unprivileged reader sees the header only, because probing
// undefined registers wedges some functions. Access past the window is a
// short read, never an error.

use vfs::{KResult, VfsError};

/// Config-space bytes visible to a reader of this function. # C: O(1)
pub(crate) fn visible_size(dev: &drv::Device, privileged: bool) -> usize {
    let header_type = dev.pci.unwrap_or_default().header_type;
    pci::visible_size(privileged, header_type)
}

/// Serve a `config` read. # C: O(n)
pub(crate) fn read(dev: &drv::Device, privileged: bool, off: u64, buf: &mut [u8]) -> KResult<usize> {
    let n = pci::span(visible_size(dev, privileged), off, buf.len());
    if n == 0 { return Ok(0); }
    if !drv::pci_config_read(&dev.addr, off as usize, &mut buf[..n]) { return Err(VfsError::Eio); }
    Ok(n)
}

/// Serve a `config` write. Writes reach the whole space — the mode already
/// confines them to the owner. # C: O(n)
pub(crate) fn write(dev: &drv::Device, off: u64, buf: &[u8]) -> KResult<usize> {
    let n = pci::span(pci::uapi::CFG_SPACE_SIZE, off, buf.len());
    if n == 0 { return Ok(0); }
    if !drv::pci_config_write(&dev.addr, off as usize, &buf[..n]) { return Err(VfsError::Eio); }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use std::sync::{Mutex, Once, OnceLock};

    const FAKE_ADDR: &str = "0000:00:1d.7";

    fn space() -> &'static Mutex<[u8; pci::uapi::CFG_SPACE_SIZE]> {
        static SPACE: OnceLock<Mutex<[u8; pci::uapi::CFG_SPACE_SIZE]>> = OnceLock::new();
        SPACE.get_or_init(|| {
            let mut s = [0u8; pci::uapi::CFG_SPACE_SIZE];
            for (idx, byte) in s.iter_mut().enumerate() { *byte = idx as u8; }
            Mutex::new(s)
        })
    }

    fn fake_read(addr: &str, off: usize, buf: &mut [u8]) -> bool {
        if addr != FAKE_ADDR { return false; }
        buf.copy_from_slice(&space().lock().unwrap()[off..off + buf.len()]);
        true
    }

    fn fake_write(addr: &str, off: usize, buf: &[u8]) -> bool {
        if addr != FAKE_ADDR { return false; }
        space().lock().unwrap()[off..off + buf.len()].copy_from_slice(buf);
        true
    }

    fn dev() -> drv::Device {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| drv::set_pci_config_hooks(fake_read, fake_write));
        drv::Device::new("pci", FAKE_ADDR.to_string(), 0x1AF4, 0x1050, 0x03_00_00)
            .with_pci_ident(drv::PciIdent {
                header_type: pci::uapi::HEADER_TYPE_NORMAL,
                ..drv::PciIdent::default()
            })
    }

    #[test]
    fn unprivileged_reader_sees_the_header_window_only() {
        let d = dev();
        assert_eq!(visible_size(&d, false), pci::uapi::CFG_SPACE_UNPRIV_SIZE);
        assert_eq!(visible_size(&d, true), pci::uapi::CFG_SPACE_SIZE);
        let mut buf = [0u8; pci::uapi::CFG_SPACE_SIZE];
        assert_eq!(read(&d, false, 0, &mut buf), Ok(pci::uapi::CFG_SPACE_UNPRIV_SIZE));
        assert_eq!(read(&d, true, 0, &mut buf), Ok(pci::uapi::CFG_SPACE_SIZE));
    }

    #[test]
    fn read_past_the_window_is_short_then_empty() {
        let d = dev();
        let mut buf = [0u8; 8];
        assert_eq!(read(&d, false, 60, &mut buf), Ok(4));
        assert_eq!(&buf[..4], &[60, 61, 62, 63]);
        assert_eq!(read(&d, false, 64, &mut buf), Ok(0));
        assert_eq!(read(&d, false, 4096, &mut buf), Ok(0));
        assert_eq!(read(&d, true, 4092, &mut buf), Ok(4));
        assert_eq!(read(&d, true, 4096, &mut buf), Ok(0));
    }

    #[test]
    fn read_serves_the_bytes_at_the_requested_offset() {
        let d = dev();
        let mut buf = [0u8; 4];
        assert_eq!(read(&d, true, 0x2c, &mut buf), Ok(4));
        assert_eq!(buf, [0x2c, 0x2d, 0x2e, 0x2f]);
    }

    #[test]
    fn write_round_trips_and_clamps_at_the_end_of_config_space() {
        let d = dev();
        assert_eq!(write(&d, 0x80, &[0xAA, 0xBB]), Ok(2));
        let mut buf = [0u8; 2];
        assert_eq!(read(&d, true, 0x80, &mut buf), Ok(2));
        assert_eq!(buf, [0xAA, 0xBB]);
        assert_eq!(write(&d, 4095, &[1, 2, 3, 4]), Ok(1));
        assert_eq!(write(&d, 4096, &[1]), Ok(0));
    }

    #[test]
    fn a_function_with_no_accessor_reports_io_error() {
        let d = dev();
        let absent = drv::Device::new("pci", "0000:00:1e.0".to_string(), 0, 0, 0);
        let mut buf = [0u8; 4];
        assert_eq!(read(&absent, true, 0, &mut buf), Err(VfsError::Eio));
        assert_eq!(write(&absent, 0, &[0]), Err(VfsError::Eio));
        // The fake stays wired for the addresses it owns.
        assert_eq!(read(&d, true, 0, &mut buf), Ok(4));
    }
}
