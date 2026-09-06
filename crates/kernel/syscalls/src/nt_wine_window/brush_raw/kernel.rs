use super::Operation;

/// Preserve native handle/BOOL return conventions without swallowing owner failures. # C: canonical brush operation cost
pub(crate) fn dispatch(operation: Operation) -> u64 {
    match operation {
        Operation::CreateSolid { color } => crate::nt_gdi::create_solid_brush_for_current(color).map(u64::from).unwrap_or(0),
        Operation::Select { dc, brush } => crate::nt_gdi::select_brush_for_current(dc, brush).map(u64::from).unwrap_or(0),
        Operation::PatBlt { dc, x, y, width, height, rop } => u64::from(crate::nt_gdi::pat_blt_for_current(dc, x, y, width, height, rop).is_ok()),
    }
}
