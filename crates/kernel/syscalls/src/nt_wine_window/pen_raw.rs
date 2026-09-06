//! Typed pen/primitive ingress; canonical owners perform allocation, selection and raster writes.
use ipc::win32_gdi::Rect;
pub(crate) const CREATE_PEN:u64=0x10ba;
pub(crate) const SELECT_PEN:u64=0x126f;
pub(crate) const LINE_TO:u64=0x123a;
pub(crate) const RECTANGLE:u64=0x1259;
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub(crate) enum PenCall {
    Create {style:i32,width:i32,colorref:u32},
    Select {dc:u64,pen:u64},
    Line {dc:u64,x:i32,y:i32},
    Rectangle {dc:u64,rect:Rect},
}
/// Preserve handle width and truncate Windows scalar arguments only. # C: O(1) plus owner call
pub(crate) fn route(ordinal:u64,args:&[u64],execute:impl FnOnce(PenCall)->u64)->Option<u64> {
    let call=match ordinal {
        CREATE_PEN=>{let [style,width,colorref,_brush,..]=args else{return Some(0);};
            PenCall::Create {style:*style as i32,width:*width as i32,colorref:*colorref as u32}},
        SELECT_PEN=>{let [dc,pen,..]=args else{return Some(0);};PenCall::Select {dc:*dc,pen:*pen}},
        LINE_TO=>{let [dc,x,y,..]=args else{return Some(0);};PenCall::Line {dc:*dc,x:*x as i32,y:*y as i32}},
        RECTANGLE=>{let [dc,left,top,right,bottom,..]=args else{return Some(0);};
            PenCall::Rectangle {dc:*dc,rect:Rect {left:*left as i32,top:*top as i32,right:*right as i32,bottom:*bottom as i32}}},
        _=>return None,
    };
    Some(execute(call))
}
#[cfg(target_os="oxide-kernel")]
#[path="pen_raw/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path="tests/pen_raw.rs"]
mod tests;
