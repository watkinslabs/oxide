use super::*;
use syscall::nt_compositor::Rect;
fn monitor(x:i32,y:i32,width:u32,height:u32)->Monitor {
    Monitor {monitor:Rect{x,y,width,height},workarea:Rect{x,y:y+30,width,height:height-30}}
}
#[test]
fn desktop_bounds_follow_real_monitor_updates_not_workarea_or_primary_guess() {
    assert_eq!(bounds(&[monitor(-1920,0,1920,1080),monitor(0,0,2560,1440)]),
        Some(WindowRect {left:-1920,top:0,right:2560,bottom:1440}));
    assert_eq!(bounds(&[monitor(120,80,1280,720)]),Some(WindowRect {left:120,top:80,right:1400,bottom:800}));
    assert_eq!(bounds(&[]),None);
}
#[test]
fn invalid_or_unrepresentable_monitor_union_has_no_desktop_fallback() {
    assert_eq!(bounds(&[monitor(0,0,0,1080)]),None);
    assert_eq!(bounds(&[monitor(i32::MAX,0,10,1080)]),None);
    assert_eq!(bounds(&[monitor(i32::MIN,0,10,1080),monitor(0,0,10,1080)]),None);
}
