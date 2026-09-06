use super::abi::*;
use ipc::win32_window::WindowRect;
use syscall::nt_compositor::Rect;

pub(super) trait Owner {
    fn context(&mut self, hwnd: u64) -> Option<Context>;
    /// Commit must revalidate canonical references and execute retained flags.
    fn commit(&mut self, request: Request) -> bool;
}
fn order(value: u64) -> Order {
    match value { 0 => Order::Top, 1 => Order::Bottom,
        0xffff | 0xffff_ffff | u64::MAX => Order::Topmost,
        0xfffe | 0xffff_fffe | 0xffff_ffff_ffff_fffe => Order::NotTopmost,
        hwnd => Order::After(hwnd) }
}

/// All seven raw arguments consumed; ignored coordinates cannot invalidate the request. # C: O(owner lookup + commit)
pub(super) fn set(owner: &mut impl Owner, args: &[u64; 7]) -> u64 {
    let hwnd = args[0];
    let Some(context) = owner.context(hwnd) else { return 0; };
    let mut flags = args[6] as u32;
    let mut insert = if flags & NOZORDER != 0 { None } else { Some(order(args[1])) };
    if let Some(Order::After(after)) = insert {
        let Some(sibling) = owner.context(after) else { return 0; };
        if sibling.parent != context.parent { return 1; }
        if after == hwnd { insert = None; flags |= NOZORDER; }
    }
    let old = context.rect;
    let (x,y) = if flags & NOMOVE != 0 { (old.left,old.top) }
        else { ((args[2] as i32).clamp(COORD_MIN,COORD_MAX),(args[3] as i32).clamp(COORD_MIN,COORD_MAX)) };
    let (width,height) = if flags & NOSIZE != 0 {
        let Some(w) = old.right.checked_sub(old.left) else { return 0; };
        let Some(h) = old.bottom.checked_sub(old.top) else { return 0; }; (w,h)
    } else { ((args[4] as i32).clamp(0,COORD_MAX),(args[5] as i32).clamp(0,COORD_MAX)) };
    let Ok(width) = u32::try_from(width) else { return 0; };
    let Ok(height) = u32::try_from(height) else { return 0; };
    if (Rect { x,y,width,height }).validate_window().is_err() { return 0; }
    let rect = WindowRect { left:x,top:y,right:x+width as i32,bottom:y+height as i32 };
    if context.visible { flags &= !SHOW; } else { flags &= !HIDE; if flags & SHOW == 0 { flags |= NOREDRAW; } }
    let visible = if flags & HIDE != 0 { Some(false) } else if flags & SHOW != 0 { Some(true) } else { None };
    if context.style & (WS_CHILD | WS_POPUP) != WS_CHILD && flags & (NOACTIVATE | HIDE) == 0
        && (flags & NOZORDER != 0 || !matches!(insert,Some(Order::Topmost | Order::NotTopmost))) {
        insert = Some(Order::Top); flags &= !NOZORDER;
    }
    u64::from(owner.commit(Request { hwnd,rect,order:insert,visible,flags }))
}
