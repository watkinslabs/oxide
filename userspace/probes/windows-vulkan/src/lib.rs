//! Windows-process Vulkan capability façade over the tagged NT boundary.

mod present;
pub use present::{HandoffResult, PresentError, PresentSession, SurfaceDescription, SurfaceFormat, SurfaceHandoff, SurfaceState};

use std::io;
use syscall::nt::{NtService, NtVulkanCapability};

const STATUS_FAILURE_MASK: u64 = 0x8000_0000;
pub(crate) const CAPABILITY_VERSION: u32 = 1;
pub(crate) const RENDER_NODE: u32 = 1;
pub(crate) const THREE_D: u32 = 2;
pub(crate) const KNOWN_CAPABILITY_FLAGS: u32 = RENDER_NODE | THREE_D;
pub(crate) const XRGB8888: u64 = 1;
pub(crate) const ARGB8888: u64 = 2;
pub(crate) const KNOWN_FORMATS: u64 = XRGB8888 | ARGB8888;

#[derive(Debug)]
pub enum VulkanError { Unsupported, InvalidImage(pe::Error), MissingVulkanImport, Status(u64), Host(io::Error) }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Capability { pub version: u32, pub render_node: bool, pub three_d: bool, pub max_width: u32, pub max_height: u32, pub format_mask: u64 }

impl Capability {
    /// Validate the fixed NT record before a Windows graphics layer consumes it. # C: O(1)
    pub fn from_native(value: NtVulkanCapability) -> Result<Self, VulkanError> {
        let capability = Self { version: value.version, render_node: value.flags & RENDER_NODE != 0, three_d: value.flags & THREE_D != 0, max_width: value.max_width, max_height: value.max_height, format_mask: value.format_mask };
        if capability.version != CAPABILITY_VERSION || value.flags & !KNOWN_CAPABILITY_FLAGS != 0
            || !capability.render_node || !capability.three_d || capability.max_width == 0
            || capability.max_height == 0 || capability.format_mask == 0
            || capability.format_mask & !KNOWN_FORMATS != 0 {
            return Err(VulkanError::Unsupported);
        }
        Ok(capability)
    }
}

/// Validated handoff from one 64-bit PE image to the native Vulkan WSI owner.
/// The image is parsed by the shared PE owner before any window or queue state
/// is admitted; a generic PE cannot accidentally enter the Vulkan path.
pub struct VulkanLaunchHandoff {
    image_size: u64,
    entry_rva: u32,
    session: PresentSession,
}

impl VulkanLaunchHandoff {
    /// Admit a PE32+ image that explicitly imports the Windows Vulkan ABI and
    /// bind it to one already-admitted native surface.
    /// # C: O(image bytes + WSI admission)
    pub fn admit(image: &[u8], capability: Capability, surface: SurfaceDescription) -> Result<Self, VulkanError> {
        let parsed = pe::parse(image).map_err(VulkanError::InvalidImage)?;
        let imports = parsed.imports().map_err(VulkanError::InvalidImage)?;
        if !imports.iter().any(|import| import.name.eq_ignore_ascii_case(b"vulkan-1.dll")) {
            return Err(VulkanError::MissingVulkanImport);
        }
        let session = PresentSession::create(capability, surface).map_err(|_| VulkanError::Unsupported)?;
        Ok(Self { image_size: image.len() as u64, entry_rva: parsed.entry_rva, session })
    }

    /// Return the PE facts and the exclusive present session after admission.
    /// # C: O(1)
    pub fn image_facts(&self) -> (u64, u32) { (self.image_size, self.entry_rva) }

    /// Transfer the admitted WSI session to the launch owner.
    /// # C: O(1)
    pub fn into_session(self) -> PresentSession { self.session }
}

/// Query the native DRM/Vulkan admission contract from the current Windows process. # C: O(1) plus NT service
pub fn query() -> Result<Capability, VulkanError> {
    let mut native = NtVulkanCapability { version: 0, flags: 0, max_width: 0, max_height: 0, format_mask: 0 };
    // SAFETY: the tagged selector and fixed 64-bit argument ABI are stable;
    // native remains writable for the synchronous kernel copy.
    let result = unsafe { libc::syscall(NtService::QueryVulkanCapability.entry() as libc::c_long, (&mut native as *mut NtVulkanCapability) as u64, std::mem::size_of::<NtVulkanCapability>() as u64) };
    if result == -1 { return Err(VulkanError::Host(io::Error::last_os_error())); }
    let status = result as u64;
    if status & STATUS_FAILURE_MASK != 0 { return Err(if status == 0xc000_00bb { VulkanError::Unsupported } else { VulkanError::Status(status) }); }
    Capability::from_native(native)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> NtVulkanCapability { NtVulkanCapability { version: 1, flags: 3, max_width: 4096, max_height: 2160, format_mask: 3 } }

    #[test]
    fn valid_native_capability_is_consumable_by_windows_graphics() { assert_eq!(Capability::from_native(valid()).unwrap().max_width, 4096); }

    #[test]
    fn unsupported_capability_is_not_downgraded_to_software_claim() {
        assert!(matches!(Capability::from_native(NtVulkanCapability { flags: 1, ..valid() }), Err(VulkanError::Unsupported)));
        assert!(matches!(Capability::from_native(NtVulkanCapability { format_mask: 0, ..valid() }), Err(VulkanError::Unsupported)));
        assert!(matches!(Capability::from_native(NtVulkanCapability { version: 2, ..valid() }), Err(VulkanError::Unsupported)));
    }

    #[test]
    fn native_capability_rejects_unknown_flags_and_formats() {
        assert!(matches!(Capability::from_native(NtVulkanCapability { flags: 7, ..valid() }), Err(VulkanError::Unsupported)));
        assert!(matches!(Capability::from_native(NtVulkanCapability { format_mask: 4, ..valid() }), Err(VulkanError::Unsupported)));
        assert!(matches!(Capability::from_native(NtVulkanCapability { max_width: 0, ..valid() }), Err(VulkanError::Unsupported)));
        assert!(matches!(Capability::from_native(NtVulkanCapability { max_height: 0, ..valid() }), Err(VulkanError::Unsupported)));
    }

    #[test]
    fn native_capability_preserves_all_admitted_fields() {
        let capability = Capability::from_native(valid()).unwrap();
        assert_eq!((capability.version, capability.render_node, capability.three_d), (1, true, true));
        assert_eq!((capability.max_width, capability.max_height, capability.format_mask), (4096, 2160, 3));
    }

    fn pe_image(import: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![0u8; 0x800];
        b[..2].copy_from_slice(b"MZ"); b[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0"); b[0x84..0x86].copy_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        let opt = 0x98; let sec = 0x188;
        b[opt..opt + 2].copy_from_slice(&pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        b[opt + 16..opt + 20].copy_from_slice(&0x1010u32.to_le_bytes()); b[opt + 24..opt + 32].copy_from_slice(&0x1000_0000u64.to_le_bytes());
        b[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); b[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        b[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); b[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); b[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        b[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); b[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        b[sec + 36..sec + 40].copy_from_slice(&(pe::SectionFlags::MEM_READ | pe::SectionFlags::MEM_EXECUTE).to_le_bytes()); b[0x410] = 0xcc;
        if let Some(name) = import {
            let dir = opt + 112 + pe::IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
            b[dir..dir + 4].copy_from_slice(&0x1100u32.to_le_bytes()); b[dir + 4..dir + 8].copy_from_slice(&40u32.to_le_bytes());
            b[0x50c..0x510].copy_from_slice(&0x1160u32.to_le_bytes()); b[0x510..0x514].copy_from_slice(&0x1180u32.to_le_bytes());
            b[0x560..0x560 + name.len()].copy_from_slice(name); b[0x560 + name.len()] = 0;
        }
        b
    }

    fn capability() -> Capability { Capability { version: 1, render_node: true, three_d: true, max_width: 4096, max_height: 2160, format_mask: XRGB8888 } }

    fn surface() -> SurfaceDescription {
        SurfaceDescription { session: 3, window: 41, window_owner: 7, device: 11, queue: 13, resource: 17, device_ready: true, surface_alive: true, present_supported: true, width: 1280, height: 720, format: SurfaceFormat::Xrgb8888 }
    }

    #[test]
    fn launch_handoff_requires_a_valid_x64_vulkan_image() {
        let handoff = VulkanLaunchHandoff::admit(&pe_image(Some(b"vulkan-1.dll")), capability(), surface()).unwrap();
        assert_eq!(handoff.image_facts(), (0x800, 0x1010));
        assert_eq!(handoff.into_session().state(), SurfaceState::Ready);
    }

    #[test]
    fn launch_handoff_rejects_non_vulkan_and_malformed_images() {
        assert!(matches!(VulkanLaunchHandoff::admit(&pe_image(None), capability(), surface()), Err(VulkanError::MissingVulkanImport)));
        assert!(matches!(VulkanLaunchHandoff::admit(b"not-pe", capability(), surface()), Err(VulkanError::InvalidImage(_))));
        let mut pe32 = pe_image(Some(b"vulkan-1.dll")); pe32[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        assert!(matches!(VulkanLaunchHandoff::admit(&pe32, capability(), surface()), Err(VulkanError::InvalidImage(_))));
        let mut broken_import = pe_image(Some(b"vulkan-1.dll")); broken_import[0x50c..0x510].copy_from_slice(&0x2fffu32.to_le_bytes());
        assert!(matches!(VulkanLaunchHandoff::admit(&broken_import, capability(), surface()), Err(VulkanError::InvalidImage(_))));
    }

    #[test]
    fn launch_handoff_rejects_surface_that_native_capability_cannot_admit() {
        assert!(matches!(VulkanLaunchHandoff::admit(&pe_image(Some(b"vulkan-1.dll")), capability(), SurfaceDescription { width: 0, ..surface() }), Err(VulkanError::Unsupported)));
    }
}
