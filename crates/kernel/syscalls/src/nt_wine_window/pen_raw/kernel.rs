use super::PenCall;
/// No GDI work at raw dispatch; each operation calls its canonical owner. # C: owner operation cost
pub(crate) fn route(ordinal:u64,args:&[u64])->Option<u64> {
    super::route(ordinal,args,|call|match call {
        PenCall::Create {style,width,colorref}=>crate::nt_gdi::create_pen_for_current(style,width,colorref),
        PenCall::Select {dc,pen}=>crate::nt_gdi::select_pen_for_current(dc,pen),
        PenCall::Line {dc,x,y}=>crate::nt_gdi::pen_line_for_current(dc,x,y),
        PenCall::Rectangle {dc,rect}=>crate::nt_gdi::pen_rectangle_for_current(dc,rect),
    })
}
