//! Windows-process Vulkan capability façade over the tagged NT boundary.

mod present;
pub use present::{HandoffResult, PresentError, PresentSession, SurfaceDescription, SurfaceFormat, SurfaceHandoff, SurfaceState};

use std::io;
use syscall::nt::{NtService, NtVulkanCapability};

const STATUS_FAILURE_MASK: u64 = 0x8000_0000;

#[derive(Debug)]
pub enum VulkanError { Unsupported, Status(u64), Host(io::Error) }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Capability { pub version: u32, pub render_node: bool, pub three_d: bool, pub max_width: u32, pub max_height: u32, pub format_mask: u64 }

impl Capability {
    /// Validate the fixed NT record before a Windows graphics layer consumes it. # C: O(1)
    pub fn from_native(value: NtVulkanCapability) -> Result<Self, VulkanError> {
        let capability = Self { version: value.version, render_node: value.flags & 1 != 0, three_d: value.flags & 2 != 0, max_width: value.max_width, max_height: value.max_height, format_mask: value.format_mask };
        if capability.version != 1 || !capability.render_node || !capability.three_d || capability.max_width == 0 || capability.max_height == 0 || capability.format_mask == 0 { return Err(VulkanError::Unsupported); }
        Ok(capability)
    }
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
}
