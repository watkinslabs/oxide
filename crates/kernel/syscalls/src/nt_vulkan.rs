//! Native Windows Vulkan capability boundary backed by the DRM owner.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{self, NtCall, NtVulkanCall, NtVulkanCapability};
use crate::nt_vulkan_policy::{self, Facts};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

/// Query capability from the primary DRM driver without fabricating a Vulkan
/// implementation. The driver remains the sole owner of GPU state.
/// # C: O(N_formats) plus one DRM capability query
pub fn dispatch(call: NtCall) -> Option<u64> {
    let NtVulkanCall::QueryCapability { info, length } = nt::decode_vulkan(call).ok()?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let status = {
        let Some(card) = drm::primary_card() else {
            return Some(nt_vulkan_policy::STATUS_NOT_SUPPORTED);
        };
        let three_d = card.virtgpu_getparam(drm::VIRTGPU_PARAM_3D_FEATURES).is_some_and(|v| v == Ok(1));
        let formats = card.scanout_formats();
        let format_mask = formats.iter().fold(0u64, |mask, format| match *format {
            drm::DRM_FORMAT_XRGB8888 => mask | 1,
            drm::DRM_FORMAT_ARGB8888 => mask | 2,
            _ => mask,
        });
        let (_, max_width, _, max_height) = card.dim_bounds();
        let facts = Facts { render_node: card.supports_render_node(), three_d, max_width, max_height, format_mask };
        let status = nt_vulkan_policy::query_status(length as usize, facts);
        if status == nt_vulkan_policy::STATUS_SUCCESS {
            let raw = nt_vulkan_policy::encode(facts);
            // SAFETY: NT user pointer and exact record length were validated by
            // the decoder; copy_to_user performs the active-AS fault recovery.
            if uaccess::copy_to_user(info.as_u64(), &raw).is_err() { return Some(STATUS_INVALID_PARAMETER); }
        }
        status
    };
    Some(status)
}

#[allow(dead_code)]
fn _abi_is_fixed_width() { let _ = core::mem::size_of::<NtVulkanCapability>(); }
