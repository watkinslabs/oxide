use super::*;
use ipc::win32_gdi::*;
use ipc::win32_window::{PaintRegion,WindowRect};
use syscall::nt_gdi_client as abi;
use nt_gdi::client::ClientBinding;
fn fixture()->(GdiManager,u32,ClientBinding){
    MEMORY.with(|m|{let mut m=m.borrow_mut();m.bytes.fill(0);m.writes=0;m.fail_write=false;});
    put_user_u64(PEB+abi::PEB_TABLE_OFFSET,TABLE).unwrap();
    let binding=ClientBinding{table_base:TABLE,attr_base:ATTRS,table_bytes:abi::TABLE_BYTES,attr_bytes:abi::DC_ATTR_BYTES,attr_stride:abi::DC_ATTR_SIZE};
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();(g,backing,binding)
}
fn request(backing:u32,owner:LeaseOwner,flags:u32)->DcLeaseRequest{
    DcLeaseRequest{hwnd:7,backing_hwnd:7,backing,origin:(0,0),screen_origin:(0,0),width:4,height:4,
        visible:PaintRegion::from_rect(WindowRect{left:0,top:0,right:4,bottom:4}).unwrap(),owner,flags,clip_handle:0}
}
fn bytes(binding:ClientBinding,dc:u32)->[u8;abi::DC_ATTR_SIZE]{let mut b=[0;abi::DC_ATTR_SIZE];copy_from_user(&mut b,binding.dc_attr_address(dc).unwrap()).unwrap();b}
fn preserve(extended:bool,reuse:bool){
    for(owner,flags)in[(LeaseOwner::Window(7),0),(LeaseOwner::Class(9),0),(LeaseOwner::Cached,DCX_CACHE|DCX_NORESETATTRS)]{
        let(mut g,backing,binding)=fixture();let dc=g.acquire_dc_lease(request(backing,owner,flags)).unwrap();
        projection::acquire(&binding,dc,1,g.text_state(dc).unwrap(),false).unwrap();
        let mut shared=bytes(binding,dc);
        shared[abi::dc::BACKGROUND_MODE..abi::dc::BACKGROUND_MODE+2].copy_from_slice(&1u16.to_le_bytes());
        shared[abi::dc::ROP_MODE..abi::dc::ROP_MODE+2].copy_from_slice(&7u16.to_le_bytes());
        if extended{shared[abi::dc::CHAR_EXTRA..abi::dc::CHAR_EXTRA+4].copy_from_slice(&13i32.to_le_bytes());}
        shared[abi::dc::BRUSH_COLOR..abi::dc::BRUSH_COLOR+4].copy_from_slice(&0x123456u32.to_le_bytes());
        copy_to_user(binding.dc_attr_address(dc).unwrap(),&shared).unwrap();
        let font=g.create_font(Font{height:19,width:0,weight:400,italic:false}).unwrap();g.select_font(dc,font).unwrap();
        let selected=g.text_state(dc).unwrap().font;let reset=g.dc_lease_resets_on_release(dc).unwrap();
        let state=g.release_dc_lease_state(dc).unwrap();let writes=MEMORY.with(|m|m.borrow().writes);
        projection::release(&binding,dc,1,state,reset).unwrap();
        assert_eq!(MEMORY.with(|m|m.borrow().writes),writes);assert_eq!(bytes(binding,dc),shared);
        if !reuse{continue;}
        assert_eq!(g.acquire_dc_lease(request(backing,owner,flags)).unwrap(),dc);
        projection::acquire(&binding,dc,1,g.text_state(dc).unwrap(),true).unwrap();
        assert_eq!(bytes(binding,dc),shared);assert_eq!(g.text_state(dc).unwrap().font,selected);
    }
}
#[test]
fn actual_binding_preserves_shared_own_class_and_noreset_across_release_reuse(){preserve(true,true);}
#[test]
fn actual_binding_release_preserves_all_shared_attributes(){preserve(true,false);}
#[test]
fn actual_binding_reuse_preserves_supported_shared_attributes(){preserve(false,true);}
#[test]
fn actual_binding_cached_reset_reinitializes_complete_projection(){
    let(mut g,backing,binding)=fixture();let dc=g.acquire_dc_lease(request(backing,LeaseOwner::Cached,DCX_CACHE)).unwrap();
    projection::acquire(&binding,dc,1,g.text_state(dc).unwrap(),false).unwrap();let default=bytes(binding,dc);
    copy_to_user(binding.dc_attr_address(dc).unwrap()+abi::dc::ROP_MODE as u64,&7u16.to_le_bytes()).unwrap();
    let reset=g.dc_lease_resets_on_release(dc).unwrap();assert!(reset);
    projection::release(&binding,dc,1,g.release_dc_lease_state(dc).unwrap(),reset).unwrap();
    assert_eq!(bytes(binding,dc),default);
}

#[test]
fn actual_first_publication_of_empty_dc_keeps_valid_shared_metadata(){
    for(width,height)in[(0,0),(0,4),(4,0)]{
        let(mut g,_,binding)=fixture();let backing=g.acquire_window_dc(8,width,height).unwrap();
        let mut req=request(backing,LeaseOwner::Cached,DCX_CACHE);req.hwnd=8;req.backing_hwnd=8;
        req.width=width;req.height=height;req.visible=PaintRegion::default();
        let dc=g.acquire_dc_lease(req).unwrap();
        projection::acquire(&binding,dc,1,g.text_state(dc).unwrap(),false).unwrap();
        assert_eq!(binding.text_snapshot(dc).unwrap(),abi::DcText::default());
        let address=abi::entry_address(binding.table_base,dc&0xffff).unwrap();
        let mut entry=[0u8;abi::ENTRY_SIZE];copy_from_user(&mut entry,address).unwrap();
        assert_eq!(abi::HandleEntry::decode(&entry).unwrap().user_pointer,binding.dc_attr_address(dc).unwrap());
        assert!(g.text_metrics(dc).is_ok());assert!(g.pending_outputs().unwrap().is_empty());
        let reset=g.dc_lease_resets_on_release(dc).unwrap();
        projection::release(&binding,dc,1,g.release_dc_lease_state(dc).unwrap(),reset).unwrap();
        assert_eq!(binding.text_snapshot(dc).unwrap(),abi::DcText::default());
    }
}
