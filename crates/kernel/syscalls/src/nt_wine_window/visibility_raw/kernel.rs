/// Both raw and descriptor ingress use the same decoder and canonical owner. # C: O(processes + DCs)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    super::route(ordinal, args, crate::nt_gdi::visibility_clip_for_current, |pointer| {
        let mut bytes = [0u8; 16];
        uaccess::copy_from_user(&mut bytes, pointer).ok()?;
        Some(bytes)
    }, ipc::win32_gdi::rect_visible_in_clip)
}
