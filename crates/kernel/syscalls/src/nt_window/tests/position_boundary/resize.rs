use super::*;
use ipc::win32_window::{WindowPosition,RDW_INVALIDATE,PaintRegion};
const SWP_NOREDRAW:u32=0x0008;
fn r(x:i32,y:i32,w:i32,h:i32)->WindowRect{WindowRect{left:x,top:y,right:x+w,bottom:y+h}}
fn window(class:u32,w:i32,h:i32)->Request{
    let mut request=setup(5);let mut entries=GUI.lock();let state=&mut entries[0].state;
    let atom=state.register_class_with_style(&[65],5,0,true,class).unwrap();let id=state.create_class_atom(1,None,atom).unwrap();
    state.apply_position(1,WindowPosition{window:id,rect:r(0,0,100,50),client:Some(r(0,0,100,50)),order:None,visible:Some(true),flags:0x18,notify_geometry:false}).unwrap();
    request.hwnd=id.raw() as u64;request.rect=r(0,0,w,h);request.flags=0x0416;request
}
fn region(request:Request)->PaintRegion{GUI.lock()[0].state.erase_damage(WindowId::from_raw(request.hwnd as u32).unwrap()).unwrap().region}
#[test]fn actual_class_resize_and_callback_redraw_flags_reach_canonical_damage(){
    let _serial=SERIAL.lock().unwrap();
    for(class,result,w,h,expected)in [(0,0,110,50,r(100,0,10,50)),(2,0,110,50,r(0,0,110,50)),
        (1,0,110,50,r(100,0,10,50)),(1,0,100,60,r(0,0,100,60)),(2,0,100,60,r(0,50,100,10)),
        (0,0x100,110,50,r(0,0,110,50)),(3,0x300,100,50,r(0,0,0,0))]{
        let request=window(class,w,h);assert_eq!(apply(request,None),Outcome::Pending);
        assert_eq!(complete(cb(0),result),STATUS_PENDING);assert_eq!(complete(cb(1),0),1);
        assert_eq!(region(request),PaintRegion::from_rect(expected).unwrap());
        ENV.with(|e|assert_eq!(e.borrow().preservation.len(),1));
    }
}
#[test]fn validrects_map_pending_invalid_pixels_instead_of_validating_them(){
    let _serial=SERIAL.lock().unwrap();let request=window(0,120,60);let id=WindowId::from_raw(request.hwnd as u32).unwrap();
    GUI.lock()[0].state.redraw_damage(id,Some(&PaintRegion::from_rect(r(12,12,2,2)).unwrap()),RDW_INVALIDATE,false).unwrap();
    assert_eq!(apply(request,None),Outcome::Pending);
    ENV.with(|e|{let mut e=e.borrow_mut();let bytes=&mut e.callbacks[0].bytes;
        for(offset,rect)in [(16,r(20,20,40,20)),(32,r(10,10,40,20))]{for(i,n)in [rect.left,rect.top,rect.right,rect.bottom].into_iter().enumerate(){bytes[offset+i*4..offset+i*4+4].copy_from_slice(&n.to_le_bytes());}}
    });
    assert_eq!(complete(cb(0),0x400),STATUS_PENDING);
    let mut expected=PaintRegion::from_rect(request.rect).unwrap();expected.subtract(&PaintRegion::from_rect(r(20,20,40,20)).unwrap()).unwrap();
    expected.union(&PaintRegion::from_rect(r(22,22,2,2)).unwrap()).unwrap();assert_eq!(region(request),expected);
    ENV.with(|e|assert_eq!(e.borrow().preservation[0].3,Some([r(20,20,40,20),r(10,10,40,20)])));
    assert_eq!(complete(cb(1),0),1);
}
#[test]fn noredraw_keeps_existing_damage_and_does_not_invent_preservation(){
    let _serial=SERIAL.lock().unwrap();let mut request=window(3,120,60);request.flags|=8;
    let id=WindowId::from_raw(request.hwnd as u32).unwrap();let dirty=PaintRegion::from_rect(r(2,3,4,5)).unwrap();
    GUI.lock()[0].state.redraw_damage(id,Some(&dirty),RDW_INVALIDATE,false).unwrap();
    assert_eq!(apply(request,None),Outcome::Pending);assert_eq!(complete(cb(0),0),STATUS_PENDING);assert_eq!(region(request),dirty);
    ENV.with(|e|assert_eq!(e.borrow().preservation[0].3,None));assert_eq!(complete(cb(1),0),1);
}
#[test]fn class_redraw_uses_returned_client_extent_not_requested_window_extent(){
    let _serial=SERIAL.lock().unwrap();let request=window(3,120,70);
    assert_eq!(apply(request,None),Outcome::Pending);
    ENV.with(|e|{let mut e=e.borrow_mut();for(i,n)in [0i32,0,100,50].into_iter().enumerate(){e.callbacks[0].bytes[i*4..i*4+4].copy_from_slice(&n.to_le_bytes());}});
    assert_eq!(complete(cb(0),0x300),STATUS_PENDING);
    assert!(region(request).clipped(r(0,0,100,50)).unwrap().is_empty());
    assert!(GUI.lock()[0].state.erase_damage(WindowId::from_raw(request.hwnd as u32).unwrap()).unwrap().nonclient);
    ENV.with(|e|assert_eq!(e.borrow().preservation[0].3,Some([r(0,0,100,50);2])));
    assert_eq!(complete(cb(1),0),1);
}
#[test]fn actual_position_to_gdi_copy_preserves_pixels_before_changed_callback(){
    let _serial=SERIAL.lock().unwrap();
    for class in [0,2]{
        let request=window(class,110,50);let dc=env::nt_gdi::seed(request.hwnd as u32,100,50,0x123456);
        assert_eq!(apply(request,None),Outcome::Pending);assert_eq!(complete(cb(0),0),STATUS_PENDING);
        let pixels=env::nt_gdi::pixels(dc);assert_eq!(pixels.len(),110*50);
        for row in pixels.chunks_exact(110){assert_eq!(&row[..100],&vec![if class==0{0x123456}else{0};100]);assert_eq!(&row[100..],&[0;10]);}
        ENV.with(|e|{let e=e.borrow();assert_eq!(e.callbacks.last().unwrap().message,0x47);assert_eq!(e.preservation.len(),1);assert_eq!(e.dimensions,vec![(dc,110,50)]);});
        assert_eq!(complete(cb(1),0),1);
    }
}
#[test]fn actual_position_noredraw_resize_keeps_clean_output_clean_but_updates_projection(){
    let _serial=SERIAL.lock().unwrap();
    for flags in [0,SWP_NOREDRAW]{
        let mut request=window(3,120,60);request.flags|=flags;
        let hwnd=request.hwnd as u32;let dc=env::nt_gdi::seed(hwnd,100,50,0x123456);
        assert!(env::nt_gdi::ack(env::nt_gdi::pending(hwnd,dc).unwrap()));
        assert_eq!(apply(request,None),Outcome::Pending);assert_eq!(complete(cb(0),0),STATUS_PENDING);
        assert_eq!(env::nt_gdi::pixels(dc).len(),120*60);
        ENV.with(|e|assert_eq!(e.borrow().dimensions,vec![(dc,120,60)]));
        let pending=env::nt_gdi::pending(hwnd,dc);
        if flags==SWP_NOREDRAW{assert_eq!(pending,None);}else{assert_eq!(pending.unwrap().damage,ipc::win32_gdi::Rect{left:0,top:0,right:120,bottom:60});}
        assert_eq!(complete(cb(1),0),1);
    }
}
#[test]fn actual_position_noredraw_clips_pending_output_and_rejects_active_stale_ack(){
    let _serial=SERIAL.lock().unwrap();
    for (w,h,expected) in [(120,60,Some((80,30,100,50))),(90,40,Some((80,30,90,40))),(70,20,None)]{
        let mut request=window(3,w,h);request.flags|=SWP_NOREDRAW;
        let hwnd=request.hwnd as u32;let dc=env::nt_gdi::seed(hwnd,100,50,0x123456);
        assert!(env::nt_gdi::ack(env::nt_gdi::pending(hwnd,dc).unwrap()));
        env::nt_gdi::draw(dc,ipc::win32_gdi::Rect{left:80,top:30,right:100,bottom:50});
        let old=env::nt_gdi::pending(hwnd,dc).unwrap();assert!(env::nt_gdi::reserve(old));
        assert_eq!(apply(request,None),Outcome::Pending);assert_eq!(complete(cb(0),0),STATUS_PENDING);
        let pending=env::nt_gdi::pending(hwnd,dc);
        assert_eq!(pending.map(|p|(p.damage.left,p.damage.top,p.damage.right,p.damage.bottom)),expected);
        if let Some(token)=pending{assert!(token.generation>old.generation);assert!(!env::nt_gdi::reserve(token));}
        assert!(!env::nt_gdi::finish(old,true));assert_eq!(env::nt_gdi::pending(hwnd,dc),pending);
        if let Some(token)=pending{assert!(env::nt_gdi::reserve(token));assert!(env::nt_gdi::finish(token,true));}
        assert_eq!(complete(cb(1),0),1);
    }
}
#[test]fn actual_position_noredraw_unchanged_backing_keeps_existing_output_token(){
    let _serial=SERIAL.lock().unwrap();let mut request=window(3,100,50);request.flags|=SWP_NOREDRAW;
    let hwnd=request.hwnd as u32;let dc=env::nt_gdi::seed(hwnd,100,50,0x123456);let pending=env::nt_gdi::pending(hwnd,dc);
    assert_eq!(apply(request,None),Outcome::Pending);assert_eq!(complete(cb(0),0),STATUS_PENDING);
    assert_eq!(env::nt_gdi::pending(hwnd,dc),pending);assert_eq!(env::nt_gdi::pixels(dc),vec![0x123456;100*50]);
    assert_eq!(complete(cb(1),0),1);
}
