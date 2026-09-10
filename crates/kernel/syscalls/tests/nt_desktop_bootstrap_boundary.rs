//! Actual launch names cross namespace, desktop membership and desktop-DC owners.
use std::sync::Arc;
use sched::nt_object::{bootstrap_desktop,NtHandleTable,ThreadDesktop,namespace};
use ipc::{win32_window::{DcLeaseContext,WindowRect,handle_space},win32_gdi::{GdiManager,DcLeaseRequest}};
#[path="../src/nt_desktop_names.rs"]
mod names;

#[test]
fn launch_path_attaches_shared_desktop_and_acquires_screen_dc(){
    let first=NtHandleTable::new();let second=NtHandleTable::new();
    let a=bootstrap_desktop(&first,names::INTERACTIVE_STATION,names::DEFAULT_DESKTOP,names::STATION_ACCESS,names::DESKTOP_ACCESS)
        .expect("actual launch path must have its canonical namespace parent");
    let b=bootstrap_desktop(&second,names::INTERACTIVE_STATION,names::DEFAULT_DESKTOP,names::STATION_ACCESS,names::DESKTOP_ACCESS).unwrap();
    assert!(Arc::ptr_eq(&a.station,&b.station));assert!(Arc::ptr_eq(&a.desktop,&b.desktop));
    let mut caller=ThreadDesktop::default();let mut other=ThreadDesktop::default();
    a.attach(&mut caller).unwrap();b.attach(&mut other).unwrap();
    let hwnd=a.desktop.desktop().unwrap().publish_root(handle_space::desktop_handle(0)).unwrap();
    assert_eq!(caller.resolve_root(&a.station),Ok(hwnd));assert_eq!(other.resolve_root(&b.station),Ok(hwnd));
    let c=DcLeaseContext::desktop(hwnd,WindowRect{left:0,top:0,right:1024,bottom:768}).unwrap();
    let mut gdi=GdiManager::new();
    let backing=gdi.acquire_window_dc(c.backing_hwnd,c.backing_width,c.backing_height).unwrap();
    let dc=gdi.acquire_dc_lease(DcLeaseRequest{hwnd:0,backing_hwnd:c.backing_hwnd,backing,origin:c.origin,
        screen_origin:c.screen_origin,width:c.logical_width,height:c.logical_height,visible:c.visible,
        flags:c.flags,owner:c.owner,clip_handle:0}).unwrap();
    assert!(gdi.text_metrics(dc).unwrap().height>0);gdi.release_dc_lease(dc).unwrap();
    drop(a);drop(b);
    let parent=names::INTERACTIVE_STATION.rsplit_once('\\').unwrap().0;
    assert!(namespace::lookup_directory(parent).is_some());
    assert_eq!(first.live_handle_count(),0);assert_eq!(second.live_handle_count(),0);
}
