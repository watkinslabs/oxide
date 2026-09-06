use super::*;

/// Called by default-procedure dispatch outside GUI/GDI locks. # C: O(processes + objects)
pub(crate) fn for_current(message: u32, dc: u64) -> Option<u64> {
    apply(message, |attribute, color| crate::nt_gdi::set_text_attribute_for_current(dc, attribute, color),
        |role| crate::nt_gdi::system_color_brush_for_current(role))
}
