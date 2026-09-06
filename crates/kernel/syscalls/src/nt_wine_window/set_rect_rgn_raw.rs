//! Identity-preserving rectangular region replacement ingress; 31fk§6.
use ipc::win32_gdi::Rect;
pub(crate) const SET_RECT_RGN:u64=0x1287;

/// Only coordinates truncate; handle validation belongs to the canonical owner. # C: owner replacement cost
pub(crate) fn route(ordinal:u64,args:&[u64],replace:impl FnOnce(u64,Rect)->bool)->Option<u64>{
    if ordinal!=SET_RECT_RGN{return None;}
    let [handle,left,top,right,bottom,..]=args else{return Some(0);};
    Some(u64::from(replace(*handle,Rect{left:*left as i32,top:*top as i32,right:*right as i32,bottom:*bottom as i32})))
}
#[cfg(target_os="oxide-kernel")]
#[path="set_rect_rgn_raw/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path="tests/set_rect_rgn_raw.rs"]
mod tests;
