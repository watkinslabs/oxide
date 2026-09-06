use super::Operation;

/// The raw return is a region complexity, not BOOL or NTSTATUS. # C: canonical clip operation cost
pub(crate) fn dispatch(operation: Operation) -> u64 {
    match operation {
        Operation::Intersect { dc, left, top, right, bottom } => crate::nt_gdi::intersect_clip_rect_for_current(dc, ipc::win32_gdi::Rect { left, top, right, bottom }),
        Operation::GetBox { dc, output } => crate::nt_gdi::get_app_clip_box_for_current(dc, output),
    }
}
