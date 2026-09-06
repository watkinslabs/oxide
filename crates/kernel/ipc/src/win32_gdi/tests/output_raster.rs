use crate::win32_gdi::*;
use crate::win32_window::{PaintRegion,WindowRect,ScrollState};
fn fixture()->(GdiManager,u32,u32){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,24,208).unwrap();
    let dc=g.acquire_dc_lease(DcLeaseRequest{hwnd:9,backing_hwnd:7,backing,origin:(1,1),screen_origin:(0,0),width:22,height:206,
        visible:PaintRegion::from_rect(WindowRect{left:0,top:0,right:22,bottom:206}).unwrap(),
        flags:DCX_CACHE,owner:LeaseOwner::Cached,clip_handle:0}).unwrap();(g,backing,dc)
}
fn dirty_once(g:&GdiManager,backing:u32){
    let tokens=g.pending_outputs().unwrap();assert_eq!(tokens.len(),1);let token=tokens[0];
    assert_eq!((token.hwnd,token.dc,token.generation),(7,backing,1));
    assert!(token.damage.left>=1&&token.damage.top>=1);
    assert!(token.damage.right<=23&&token.damage.bottom<=207);
    assert!(g.pixels(backing).unwrap().iter().any(|p|*p!=0));
}
#[test]
fn alpha_and_opaque_upload_each_mark_canonical_backing(){
    for alpha in[false,true]{let(mut g,backing,dc)=fixture();
        if alpha{g.blend_pixels(dc,0,0,2,2,&[0x80ffffff;4]).unwrap();}
        else{g.blit_pixels(dc,0,0,2,2,2,&[0xffffff;4]).unwrap();}
        dirty_once(&g,backing);
    }
}
#[test]
fn patblt_and_pen_line_rectangle_use_tracked_lease_raster(){
    for operation in 0..3{let(mut g,backing,dc)=fixture();
        let brush=g.create_solid_brush(0xffffff).unwrap();g.select_brush(dc,brush).unwrap();
        let pen=g.create_pen(0,1,0xffffff).unwrap();g.select_pen(dc,pen).unwrap();
        match operation{0=>g.pat_blt(dc,0,0,4,4,0x00f00021).unwrap(),
            1=>g.pen_line_to(dc,(4,4),None).unwrap(),
            _=>g.pen_rectangle(dc,Rect{left:0,top:0,right:4,bottom:4},None).unwrap()}
        dirty_once(&g,backing);
    }
}
#[test]
fn nonclient_scroll_raster_marks_real_lease_backing(){
    let(mut g,backing,dc)=fixture();
    let state=ScrollState{min:0,max:99,page:20,pos:40,track_pos:0,tracking:false,visible:true,disabled:false};
    let colors=ScrollColors{face:0xc0c0c0,highlight:0xffffff,light:0xdfdfdf,shadow:0x808080,
        dark_shadow:0x404040,text:0x010101,window:0xfefefe,track:0xaabbcc};
    assert!(matches!(g.draw_nonclient_scrollbar(dc,Rect{left:2,top:2,right:19,bottom:202},true,state,
        ScrollMetrics{arrow_size:17,dpi:96},colors,ScrollPart::None).unwrap(),ScrollDrawOutcome::Painted(_)));
    dirty_once(&g,backing);
}
#[test]
fn overlapping_bitblt_reads_snapshot_and_marks_destination_once(){
    let(mut g,backing,dc)=fixture();g.blit_pixels(dc,0,0,5,1,5,&[1,2,3,4,5]).unwrap();
    let initial=g.pending_output(7,backing).unwrap();assert!(g.acknowledge_output(initial));
    g.bitblt(dc,1,0,dc,0,0,4,1).unwrap();
    assert_eq!(&g.pixels(backing).unwrap()[25..30],&[1,1,2,3,4]);
    let token=g.pending_output(7,backing).unwrap();assert_eq!(token.generation,initial.generation+1);
    assert_eq!(token.damage,Rect{left:2,top:1,right:6,bottom:2});
}
