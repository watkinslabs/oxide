use super::*;

#[test]
fn parent_frame_readback_includes_mapped_child_drawables(){
    let mut f=Fixture::open(W,H);let whole=Rect{left:0,top:0,right:W as i32,bottom:H as i32};
    f.backend.handle_command(crate::BridgeCommand::Create{hwnd:0xb2,title:Vec::new(),
        rect:Rect{left:5,top:6,right:25,bottom:16},parent:0xb1,style:crate::styles::WS_CHILD,ex_style:0}).unwrap();
    f.backend.handle_command(crate::BridgeCommand::Show{hwnd:0xb2}).unwrap();
    f.backend.set_frame_readback(true);f.present(W,H,whole,FIRST);
    assert_eq!(f.backend.frame_readback_counts(),(1,0,0));
    let part=Rect{left:8,top:7,right:18,bottom:12};f.present(W,H,part,SECOND);
    assert_eq!(f.backend.frame_readback_counts(),(2,0,0));
    assert_eq!(f.backend.read_frame_pixels(0xb1,whole).unwrap().mismatches,0);
    let child=f.backend.xid_for(0xb2).unwrap();
    // SAFETY: fixture retains the connection and mapped child for the synchronous image reply.
    let pixels=unsafe{server_image(f.conn,child,20,10)};
    for y in 0..10{for x in 0..20{
        let expected=if (3..13).contains(&x)&&(1..6).contains(&y){SECOND}else{FIRST};
        assert_eq!(pixels[y*20+x]&0xffffff,expected);
    }}
}

#[test]
fn accepted_frame_readback_is_opt_in_and_runs_through_the_actual_bridge(){
    let mut f=Fixture::open(W,H);let whole=Rect{left:0,top:0,right:W as i32,bottom:H as i32};
    f.present(W,H,whole,FIRST);assert_eq!(f.backend.frame_readback_counts(),(0,0,0));
    f.backend.set_frame_readback(true);
    let part=Rect{left:3,top:4,right:19,bottom:12};f.present(W,H,part,SECOND);
    assert_eq!(f.backend.frame_readback_counts(),(1,0,0));
    let report=f.backend.read_frame_pixels(0xb1,whole).unwrap();
    assert_eq!(report.pixels,(W*H)as usize);assert_eq!(report.mismatches,0);assert!(report.first.is_none());
    f.backend.set_frame_readback(false);f.present(W,H,part,FIRST);
    assert_eq!(f.backend.frame_readback_counts(),(1,0,0));
}

#[test]
fn readback_detects_a_server_pixel_change_that_retained_storage_cannot_see(){
    let mut f=Fixture::open(W,H);let whole=Rect{left:0,top:0,right:W as i32,bottom:H as i32};
    f.present(W,H,whole,FIRST);
    // SAFETY: fixture retains connection/window; checked request consumes the four-byte pixel before returning.
    unsafe{
        let gc=ffi::xcb_generate_id(f.conn);ffi::xcb_create_gc(f.conn,gc,f.xid,0,ptr::null());
        let pixel=SECOND.to_le_bytes();
        let cookie=ffi::xcb_put_image_checked(f.conn,ffi::IMAGE_FORMAT_Z_PIXMAP,f.xid,gc,1,1,7,9,0,24,4,pixel.as_ptr());
        let error=ffi::xcb_request_check(f.conn,cookie);assert!(error.is_null());
        ffi::xcb_flush(f.conn); // Fixture disconnect releases its temporary GC.
    }
    let report=f.backend.read_frame_pixels(0xb1,whole).unwrap();
    assert_eq!(report.mismatches,1);assert_eq!(report.first,Some((7,9,FIRST,SECOND)));
    let(retained,_)=f.backend.retained_for_test(0xb1).unwrap();assert_eq!(retained[9*W as usize+7]&0xffffff,FIRST);
}

#[test]
fn unavailable_drawable_or_unheld_coverage_is_not_reported_as_matching(){
    let mut f=Fixture::open(W,H);let whole=Rect{left:0,top:0,right:W as i32,bottom:H as i32};
    let part=Rect{left:3,top:4,right:19,bottom:12};f.present(W,H,part,FIRST);
    assert!(f.backend.read_frame_pixels(0xb1,whole).is_err());
    assert!(f.backend.read_frame_pixels(0xb2,part).is_err());
    // SAFETY: fixture owns the mapped X window and waits for the unmap request before reading it.
    unsafe{ffi::xcb_unmap_window(f.conn,f.xid);ffi::xcb_flush(f.conn);}
    let cookie=unsafe{ffi::xcb_get_window_attributes(f.conn,f.xid)};
    let mut error=ptr::null_mut();let reply=unsafe{ffi::xcb_get_window_attributes_reply(f.conn,cookie,&mut error)};
    assert!(!reply.is_null());unsafe{libc::free(reply.cast());}
    assert!(f.backend.read_frame_pixels(0xb1,part).is_err());
}
