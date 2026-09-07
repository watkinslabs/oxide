use super::*;
use syscall::nt_compositor::Rect;
/// Base pixel of the 3x2 surface every case reads the overlay against.
const BASE:u32=0x8033_4455;
fn snapshot(generation:u64,x:i32,visible:bool)->Snapshot{Snapshot{generation,rect:Rect{x,y:0,width:1,height:2},visible,mask:if visible{vec![0xffffff;2]}else{Vec::new()}}}
/// The 3x2 surface with the overlay applied, which is what a repaint assembles
/// for the display without ever holding a second copy of the window.
fn shown(s:&Surface)->Vec<u32>{(0..2).flat_map(|y|(0..3).map(move|x|(x,y))).map(|(x,y)|BASE^s.xor_at(x,y)).collect()}
fn pristine()->Vec<u32>{vec![BASE;6]}
#[test]
fn show_move_hide_and_blink_restore_pristine_pixels(){
    let mut s=Surface::default();s.update(snapshot(1,0,true)).unwrap();let a=shown(&s);assert_eq!(a[0],0x80ccbbaa);assert_eq!(a[1],BASE);assert_eq!(a,shown(&s));
    s.update(snapshot(2,1,true)).unwrap();let moved=shown(&s);assert_eq!(moved[0],BASE);assert_eq!(moved[1],a[0]);
    s.update(snapshot(3,1,false)).unwrap();assert_eq!(shown(&s),pristine());
    s.update(snapshot(4,1,true)).unwrap();assert_eq!(shown(&s),moved);
}
#[test]
fn clipping_uses_mask_origin_and_preserves_alpha_and_padding(){
    let mut s=Surface::default();s.update(Snapshot{generation:1,rect:Rect{x:-1,y:-1,width:2,height:2},visible:true,mask:vec![1,2,3,4]}).unwrap();
    let out=shown(&s);assert_eq!(out[0],BASE^4);assert_eq!(out[1..],pristine()[1..]);
    // Pixels left of and above the surface are the overlay's own, not the surface's.
    assert_eq!(s.xor_at(-1,-1),1);assert_eq!(s.xor_at(-2,0),0);
}
#[test]
fn stale_generation_cannot_resurrect_hidden_caret_but_ordered_equal_generation_can_paint(){
    let mut s=Surface::default();s.update(snapshot(4,0,false)).unwrap();assert_eq!(s.update(snapshot(3,0,true)).unwrap(), None);assert_eq!(shown(&s),pristine());
    assert!(s.update(snapshot(4,1,true)).unwrap().is_some());assert_eq!(s.update(snapshot(4,1,true)).unwrap(), None);assert_ne!(shown(&s),pristine());
}
#[test]
fn invalid_mask_does_not_replace_current_overlay_and_offscreen_shape_clips_empty(){
    let mut s=Surface::default();s.update(snapshot(1,0,true)).unwrap();let before=shown(&s);
    let mut bad=snapshot(2,1,true);bad.mask[0]=0xff000000;assert!(s.update(bad).is_err());assert_eq!(shown(&s),before);
    s.update(snapshot(3,100,true)).unwrap();assert_eq!(shown(&s),pristine());
}
#[test]
fn a_hidden_or_offscreen_overlay_alters_no_pixel_of_the_surface(){
    let mut s=Surface::default();assert_eq!(shown(&s),pristine());assert_eq!(s.covered(),None);
    s.update(snapshot(1,0,false)).unwrap();assert_eq!(shown(&s),pristine());assert_eq!(s.covered(),None);
    s.update(snapshot(2,100,true)).unwrap();assert_eq!(shown(&s),pristine());
    s.update(snapshot(3,0,true)).unwrap();assert_ne!(shown(&s),pristine());
    assert_eq!(s.covered(),Some(Bounds{left:0,top:0,right:1,bottom:2}));
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
