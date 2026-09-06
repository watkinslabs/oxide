use super::{Order,Request};
use ipc::win32_window::WindowRect;
pub(super) const CHANGING:u64=0x30;
pub(super) const NCCALC:u64=0x31;
pub(super) const CHANGED:u64=0x32;
pub(super) const NOSIZE:u32=0x0001;
pub(super) const NOSENDCHANGING:u32=0x0400;
pub(super) const WINDOWPOS_BYTES:usize=40;
pub(super) const NCCALC_BYTES:usize=96;
pub(super) const NCCALC_POINTER:u64=48;
pub(super) const NCCALC_WINPOS:u64=56;

/// Position completion ownership; router must not duplicate callback kind values. # C: O(1)
pub(crate) fn handles_callback(kind:u64)->bool {matches!(kind,CHANGING|NCCALC|CHANGED)}

pub(super) fn after(order:Option<Order>)->u64 {
    match order {None|Some(Order::Top)=>0,Some(Order::Bottom)=>1,Some(Order::Topmost)=>u64::MAX,
        Some(Order::NotTopmost)=>u64::MAX-1,Some(Order::After(id))=>id}
}
pub(super) fn encode(p:Request)->[u8;WINDOWPOS_BYTES] {
    let mut out=[0;WINDOWPOS_BYTES];out[..8].copy_from_slice(&p.hwnd.to_le_bytes());
    out[8..16].copy_from_slice(&after(p.order).to_le_bytes());
    for (i,n) in [p.rect.left,p.rect.top,p.rect.right-p.rect.left,p.rect.bottom-p.rect.top,p.flags as i32].iter().enumerate() {
        out[16+i*4..20+i*4].copy_from_slice(&n.to_le_bytes());
    }out
}
pub(super) fn decode(bytes:&[u8;WINDOWPOS_BYTES],hwnd:u64)->Option<[u64;7]> {
    if u64::from_le_bytes(bytes[..8].try_into().ok()?)!=hwnd {return None;}
    let mut args=[0;7];args[0]=hwnd;args[1]=u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    for i in 0..5 {args[i+2]=u32::from_le_bytes(bytes[16+i*4..20+i*4].try_into().ok()?) as u64;}Some(args)
}
pub(super) fn encode_rect(rect:WindowRect)->[u8;16] {
    let mut out=[0;16];for(i,n)in [rect.left,rect.top,rect.right,rect.bottom].iter().enumerate(){out[i*4..i*4+4].copy_from_slice(&n.to_le_bytes());}out
}
pub(super) fn decode_rect(bytes:[u8;16])->Option<WindowRect> {
    let n=|i:usize|i32::from_le_bytes(bytes[i*4..i*4+4].try_into().unwrap());
    let r=WindowRect {left:n(0),top:n(1),right:n(2),bottom:n(3)};
    r.right.checked_sub(r.left).filter(|v|*v>=0)?;r.bottom.checked_sub(r.top).filter(|v|*v>=0)?;Some(r)
}

#[cfg(test)]
#[path="../tests/position_layout.rs"]
mod tests;
