//! NCCALCSIZE valid destination/source coverage; both rectangles use parent coordinates.
use ipc::win32_window::WindowRect;
const CS_VREDRAW:u32=0x0001;
const CS_HREDRAW:u32=0x0002;
const WVR_ALIGNBOTTOM:u32=0x0040;
const WVR_ALIGNRIGHT:u32=0x0080;
const WVR_HREDRAW:u32=0x0100;
const WVR_VREDRAW:u32=0x0200;
const WVR_VALIDRECTS:u32=0x0400;
const SWP_NOREDRAW:u32=0x0008;
const SWP_SHOWWINDOW:u32=0x0040;
const SWP_HIDEWINDOW:u32=0x0080;
const SWP_NOCOPYBITS:u32=0x0100;
fn extent(r:WindowRect)->Option<(i32,i32)>{Some((r.right.checked_sub(r.left).filter(|n|*n>=0)?,r.bottom.checked_sub(r.top).filter(|n|*n>=0)?))}
fn intersect(a:WindowRect,b:WindowRect)->Option<WindowRect>{
    let r=WindowRect{left:a.left.max(b.left),top:a.top.max(b.top),right:a.right.min(b.right),bottom:a.bottom.min(b.bottom)};
    (r.left<r.right&&r.top<r.bottom).then_some(r)
}
pub(super) fn valid(old:WindowRect,new:WindowRect,class_style:u32,result:u32,swp:u32,returned:[WindowRect;2])->Option<[WindowRect;2]>{
    if swp&(SWP_NOREDRAW|SWP_SHOWWINDOW|SWP_HIDEWINDOW|SWP_NOCOPYBITS)!=0{return None;}
    let (ow,oh)=extent(old)?;let(nw,nh)=extent(new)?;
    let mut flags=result;
    if class_style&CS_HREDRAW!=0{flags|=WVR_HREDRAW;}if class_style&CS_VREDRAW!=0{flags|=WVR_VREDRAW;}
    if ow==nw{flags&=!WVR_HREDRAW;}if oh==nh{flags&=!WVR_VREDRAW;}
    if flags&(WVR_HREDRAW|WVR_VREDRAW)!=0{return None;}
    let mut pair=if flags&WVR_VALIDRECTS!=0{
        flags=0;[intersect(returned[0],new)?,intersect(returned[1],old)?]
    }else{[new,old]};
    let(dw,dh)=extent(pair[0])?;let(sw,sh)=extent(pair[1])?;let(w,h)=(dw.min(sw),dh.min(sh));
    if w==0||h==0{return None;}
    for r in &mut pair{
        if flags&WVR_ALIGNRIGHT!=0{r.left=r.right.checked_sub(w)?;}else{r.right=r.left.checked_add(w)?;}
        if flags&WVR_ALIGNBOTTOM!=0{r.top=r.bottom.checked_sub(h)?;}else{r.bottom=r.top.checked_add(h)?;}
    }Some(pair)
}
#[cfg(test)]
#[path="tests/nccalc.rs"]mod tests;
