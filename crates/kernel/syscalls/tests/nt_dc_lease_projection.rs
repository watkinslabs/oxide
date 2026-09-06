//! Canonical leases joined to production projection policy and actual shared byte codec.
#[path = "../src/nt_gdi/dc_lease/projection.rs"]
mod projection;
#[path = "../src/nt_gdi/client/lease_geometry.rs"]
mod lease_geometry;
use std::cell::RefCell;
use ipc::win32_gdi::*;
use ipc::win32_window::{PaintRegion,WindowRect};
use syscall::nt_gdi_client as abi;

struct Shared(RefCell<[u8;abi::DC_ATTR_SIZE]>);
impl projection::Projection for Shared {
    type Error=abi::Error;
    fn initialize(&self,dc:u32,_pid:u16,s:TextState)->Result<(),Self::Error>{
        let a=s.attributes;*self.0.borrow_mut()=abi::encode_dc_attr(dc,s.width,s.height,abi::DcText{
            foreground:a.foreground,background:a.background,alignment:a.alignment,
            background_mode:a.background_mode,current_position:a.current_position})?;Ok(())
    }
    fn geometry(&self,dc:u32,w:i32,h:i32)->Result<(),Self::Error>{
        let mut b=self.0.borrow_mut();let rect=lease_geometry::prepare(&*b,dc,w,h).map_err(|_|abi::Error::Handle)?;
        b[abi::dc::VIS_RECT+8..abi::dc::VIS_RECT+16].copy_from_slice(&rect);Ok(())
    }
}
fn request(backing:u32,owner:LeaseOwner,flags:u32)->DcLeaseRequest{
    DcLeaseRequest{hwnd:7,backing_hwnd:7,backing,origin:(0,0),screen_origin:(0,0),width:4,height:4,
        visible:PaintRegion::from_rect(WindowRect{left:0,top:0,right:4,bottom:4}).unwrap(),owner,flags,clip_handle:0}
}
#[test]
fn actual_shared_bytes_survive_owned_class_and_noreset_release_reuse(){
    for(owner,flags)in[(LeaseOwner::Window(7),0),(LeaseOwner::Class(9),0),(LeaseOwner::Cached,DCX_CACHE|DCX_NORESETATTRS)]{
        let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();
        let dc=g.acquire_dc_lease(request(backing,owner,flags)).unwrap();let shared=Shared(RefCell::new([0;abi::DC_ATTR_SIZE]));
        projection::acquire(&shared,dc,1,g.text_state(dc).unwrap(),false).unwrap();
        {let mut b=shared.0.borrow_mut();
            b[abi::dc::BACKGROUND_MODE..abi::dc::BACKGROUND_MODE+2].copy_from_slice(&1u16.to_le_bytes());
            b[abi::dc::ROP_MODE..abi::dc::ROP_MODE+2].copy_from_slice(&7u16.to_le_bytes());
            b[abi::dc::BRUSH_COLOR..abi::dc::BRUSH_COLOR+4].copy_from_slice(&0x123456u32.to_le_bytes());
            b[abi::dc::PEN_COLOR..abi::dc::PEN_COLOR+4].copy_from_slice(&0xabcdefu32.to_le_bytes());
            b[abi::dc::CHAR_EXTRA..abi::dc::CHAR_EXTRA+4].copy_from_slice(&13i32.to_le_bytes());}
        let font=g.create_font(Font{height:19,width:0,weight:400,italic:false}).unwrap();g.select_font(dc,font).unwrap();
        let expected=*shared.0.borrow();let selected=g.text_state(dc).unwrap().font;
        let reset=g.dc_lease_resets_on_release(dc).unwrap();assert!(!reset);
        let state=g.release_dc_lease_state(dc).unwrap();projection::release(&shared,dc,1,state,reset).unwrap();
        assert_eq!(*shared.0.borrow(),expected);
        assert_eq!(g.acquire_dc_lease(request(backing,owner,flags)).unwrap(),dc);
        projection::acquire(&shared,dc,1,g.text_state(dc).unwrap(),true).unwrap();
        assert_eq!(*shared.0.borrow(),expected);assert_eq!(g.text_state(dc).unwrap().font,selected);
    }
}
#[test]
fn ordinary_cached_release_resets_shared_attributes(){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();
    let dc=g.acquire_dc_lease(request(backing,LeaseOwner::Cached,DCX_CACHE)).unwrap();let shared=Shared(RefCell::new([0;abi::DC_ATTR_SIZE]));
    projection::acquire(&shared,dc,1,g.text_state(dc).unwrap(),false).unwrap();let defaults=*shared.0.borrow();
    shared.0.borrow_mut()[abi::dc::ROP_MODE]=7;
    let reset=g.dc_lease_resets_on_release(dc).unwrap();assert!(reset);
    let state=g.release_dc_lease_state(dc).unwrap();projection::release(&shared,dc,1,state,reset).unwrap();
    assert_eq!(*shared.0.borrow(),defaults);
}

#[test]
fn geometry_only_update_accepts_zero_and_preserves_all_unowned_bytes(){
    let dc=abi::TYPE_DC|42;let mut bytes=[0xa5;abi::DC_ATTR_SIZE];
    bytes[abi::dc::HDC..abi::dc::HDC+4].copy_from_slice(&dc.to_le_bytes());
    let before=bytes;
    for(w,h)in[(0,0),(0,4),(4,0),(8,9)]{
        let patch=lease_geometry::prepare(&bytes,dc,w,h).unwrap();
        bytes[abi::dc::VIS_RECT+8..abi::dc::VIS_RECT+16].copy_from_slice(&patch);
        assert_eq!(&bytes[..abi::dc::VIS_RECT+8],&before[..abi::dc::VIS_RECT+8]);
        assert_eq!(&bytes[abi::dc::VIS_RECT+16..],&before[abi::dc::VIS_RECT+16..]);
    }
    assert!(lease_geometry::prepare(&bytes,dc,-1,0).is_err());
    assert!(lease_geometry::prepare(&bytes,dc,0,-1).is_err());
    assert!(lease_geometry::prepare(&bytes,dc+1,0,0).is_err());
    assert!(lease_geometry::prepare(&bytes[..4],dc,0,0).is_err());
}
