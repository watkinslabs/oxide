use super::*;
use syscall::nt_compositor::Rect;
fn base()->Frame{Frame::new(3,2,4,vec![0x80334455;8],crate::Rect{left:0,top:0,right:3,bottom:2}).unwrap()}
fn snapshot(generation:u64,x:i32,visible:bool)->Snapshot{Snapshot{generation,rect:Rect{x,y:0,width:1,height:2},visible,mask:if visible{vec![0xffffff;2]}else{Vec::new()}}}
#[test]
fn show_move_hide_and_blink_restore_pristine_pixels(){
    let b=base();let mut s=Surface::default();s.update(snapshot(1,0,true)).unwrap();let a=s.compose(&b).unwrap();assert_eq!(a[0],0x80ccbbaa);assert_eq!(a[3],b.pixels[3]);assert_eq!(a,s.compose(&b).unwrap());
    s.update(snapshot(2,1,true)).unwrap();let moved=s.compose(&b).unwrap();assert_eq!(moved[0],b.pixels[0]);assert_eq!(moved[1],a[0]);
    s.update(snapshot(3,1,false)).unwrap();assert_eq!(s.compose(&b).unwrap(),b.pixels);
    s.update(snapshot(4,1,true)).unwrap();assert_eq!(s.compose(&b).unwrap(),moved);assert_eq!(b.pixels,vec![0x80334455;8]);
}
#[test]
fn clipping_uses_mask_origin_and_preserves_alpha_and_padding(){
    let mut s=Surface::default();s.update(Snapshot{generation:1,rect:Rect{x:-1,y:-1,width:2,height:2},visible:true,mask:vec![1,2,3,4]}).unwrap();
    let b=base();let out=s.compose(&b).unwrap();assert_eq!(out[0],b.pixels[0]^4);assert_eq!(out[1..],b.pixels[1..]);
}
#[test]
fn stale_generation_cannot_resurrect_hidden_caret_but_ordered_equal_generation_can_paint(){
    let mut s=Surface::default();s.update(snapshot(4,0,false)).unwrap();assert_eq!(s.update(snapshot(3,0,true)).unwrap(), None);assert_eq!(s.compose(&base()).unwrap(),base().pixels);
    assert!(s.update(snapshot(4,1,true)).unwrap().is_some());assert_eq!(s.update(snapshot(4,1,true)).unwrap(), None);assert_ne!(s.compose(&base()).unwrap(),base().pixels);
}
#[test]
fn new_frame_is_composited_without_reusing_old_background(){
    let mut s=Surface::default();s.update(snapshot(1,0,true)).unwrap();let mut b=base();b.pixels[0]=0x12123456;assert_eq!(s.compose(&b).unwrap()[0],0x12edcba9);
}
#[test]
fn invalid_mask_does_not_replace_current_overlay_and_offscreen_shape_clips_empty(){
    let b=base();let mut s=Surface::default();s.update(snapshot(1,0,true)).unwrap();let before=s.compose(&b).unwrap();
    let mut bad=snapshot(2,1,true);bad.mask[0]=0xff000000;assert!(s.update(bad).is_err());assert_eq!(s.compose(&base()).unwrap(),before);
    s.update(snapshot(3,100,true)).unwrap();assert_eq!(s.compose(&base()).unwrap(),base().pixels);
}
#[test]
fn no_caret_hidden_and_offscreen_borrow_the_base_without_pixel_allocation(){
    let b=base();let mut s=Surface::default();assert!(matches!(s.compose(&b).unwrap(),Cow::Borrowed(_)));
    s.update(snapshot(1,0,false)).unwrap();assert!(matches!(s.compose(&b).unwrap(),Cow::Borrowed(_)));
    s.update(snapshot(2,100,true)).unwrap();assert!(matches!(s.compose(&b).unwrap(),Cow::Borrowed(_)));
    s.update(snapshot(3,0,true)).unwrap();assert!(matches!(s.compose(&b).unwrap(),Cow::Owned(_)));
}

/// A blink alters the caret's own pixels. Reporting the whole window instead
/// costs one server request per tile of it, twice a second, for every window
/// that owns a caret.
#[test]
fn an_accepted_snapshot_reports_only_where_the_overlay_was_and_is() {
    let mut s = Surface::default();
    let at = |generation: u64, x: i32, y: i32, visible: bool| Snapshot { generation,
        rect: syscall::nt_compositor::Rect { x, y, width: 2, height: 9 }, visible,
        mask: if visible { vec![0x00ff_ffff; 18] } else { Vec::new() } };
    assert_eq!(s.update(at(1, 4, 1, true)).unwrap(), Some(Bounds { left: 4, top: 1, right: 6, bottom: 10 }));
    // A move erases where it was and draws where it is, in one coverage.
    assert_eq!(s.update(at(2, 60, 1, true)).unwrap(), Some(Bounds { left: 4, top: 1, right: 62, bottom: 10 }));
    // Hiding still owes the erase of where it was.
    assert_eq!(s.update(at(3, 60, 1, false)).unwrap(), Some(Bounds { left: 60, top: 1, right: 62, bottom: 10 }));
    // Hidden to hidden alters nothing, and a stale generation is not accepted.
    assert_eq!(s.update(at(4, 60, 1, false)).unwrap(), Some(Bounds { left: 0, top: 0, right: 0, bottom: 0 }));
    assert_eq!(s.update(at(2, 4, 1, true)).unwrap(), None);
}
