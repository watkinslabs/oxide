use super::*;
use ipc::win32_gdi::{GdiManager,TYPE_REGION};
use std::cell::RefCell;
use syscall::nt_gdi_client::HandleEntry;

fn invoke(g:&RefCell<GdiManager>,ordinal:u64,args:&[u64],write:impl FnOnce(u64,&[u8])->bool)->Option<u64> {
    route(ordinal,args,|r|g.borrow_mut().create_rect_region(r).ok(),
        |h|g.borrow().region_box(u32::try_from(h).ok()?).ok(),
        |d,a,b,m| { let (Ok(d),Ok(a))=(u32::try_from(d),u32::try_from(a)) else {return 0;};
            let b=if m==5 {0} else {let Ok(b)=u32::try_from(b) else {return 0;}; b};
            g.borrow_mut().combine_region(d,a,b,m).unwrap_or(0) },write)
}

#[test]
fn real_hrgn_projection_and_raw_create_combine_query_delete_share_identity() {
    let g=RefCell::new(GdiManager::new());
    let h=invoke(&g,CREATE_RECT_REGION,&[0xffff000000000008,8,0,0],|_,_|panic!("creation copied output")).unwrap();
    let hole=invoke(&g,CREATE_RECT_REGION,&[2,2,6,6],|_,_|false).unwrap();
    assert_eq!(h as u32 & !0xffff,TYPE_REGION); assert_ne!(h,1);
    let projected=HandleEntry::for_handle(h as u32,42,0).unwrap();
    assert_eq!(projected.kind,4); assert_eq!(projected.user_pointer,0); assert!(!projected.stock());
    assert!(HandleEntry::decode(&projected.encode().unwrap()).unwrap().client_matches(h as u32));
    assert!(g.borrow().live_handles().contains(&(h as u32)));
    assert_eq!(invoke(&g,COMBINE_REGION,&[h,h,hole,4],|_,_|false),Some(3));
    assert_eq!(invoke(&g,GET_REGION_BOX,&[h,0x123400001000],|p,bytes| {
        assert_eq!(p,0x123400001000);assert_eq!(bytes,&[0,0,0,0,0,0,0,0,8,0,0,0,8,0,0,0]);true
    }),Some(3));
    assert!(g.borrow().region_snapshot(h as u32).unwrap().clipped(ipc::win32_window::WindowRect {left:2,top:2,right:6,bottom:6}).unwrap().is_empty());
    assert_eq!(invoke(&g,COMBINE_REGION,&[hole,h,u64::MAX,0xffff000000000005],|_,_|false),Some(3));
    g.borrow_mut().delete_object(h as u32).unwrap();
    assert!(!g.borrow().live_handles().contains(&(h as u32)));
    assert_eq!(invoke(&g,GET_REGION_BOX,&[h,0x1000],|_,_|panic!("deleted object wrote output")),Some(0));
}

#[test]
fn empty_bounds_and_pointer_failures_return_region_errors_without_owner_mutation() {
    let g=RefCell::new(GdiManager::new());let h=invoke(&g,CREATE_RECT_REGION,&[1,1,1,1],|_,_|false).unwrap();
    assert_eq!(invoke(&g,GET_REGION_BOX,&[h,0x1000],|_,bytes|{assert_eq!(bytes,&[0;16]);true}),Some(1));
    for pointer in [0,u64::MAX-15] { assert_eq!(invoke(&g,GET_REGION_BOX,&[h,pointer],|_,_|panic!("bad pointer wrote")),Some(0)); }
    assert_eq!(invoke(&g,GET_REGION_BOX,&[h,0x1000],|_,_|false),Some(0));
    assert_eq!(invoke(&g,GET_REGION_BOX,&[h|(1<<32),0x1000],|_,_|panic!("wide handle truncated")),Some(0));
    for (ordinal,count) in [(CREATE_RECT_REGION,4),(GET_REGION_BOX,2),(COMBINE_REGION,4)] {
        for short in 0..count { assert_eq!(invoke(&g,ordinal,&[h;4][..short],|_,_|panic!("short args wrote")),Some(0)); }
    }
    assert_eq!(invoke(&g,0x10ba,&[],|_,_|false),None);
    assert_eq!(g.borrow().region_box(h as u32).unwrap().0,1);
}
