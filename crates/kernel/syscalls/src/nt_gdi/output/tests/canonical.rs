use super::*;
use ipc::win32_gdi::{OutputToken,DcLeaseRequest,LeaseOwner,DCX_CACHE};
use ipc::win32_window::{PaintRegion,WindowRect};

fn setup()->(Mutex<GdiManager>,u32,u32){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,4,4).unwrap();
    let dc=g.acquire_dc_lease(DcLeaseRequest{hwnd:7,backing_hwnd:7,backing,origin:(1,1),screen_origin:(0,0),
        width:2,height:2,visible:PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap(),
        flags:DCX_CACHE,owner:LeaseOwner::Cached,clip_handle:0}).unwrap();
    (Mutex::new(g),backing,dc)
}
fn capture(owner:&Mutex<GdiManager>)->Result<Option<(OutputToken,Record)>,()>{
    let mut state=owner.lock().unwrap();
    let Some(token)=state.pending_outputs().unwrap().into_iter().next()else{return Ok(None);};
    reserve_snapshot(&mut state,token)
}
#[test]
fn getdc_draw_release_without_endpaint_publishes_canonical_backing_then_becomes_clean(){
    let (owner,backing,dc)=setup();
    {let mut state=owner.lock().unwrap();
        state.fill_rect(dc,Rect{left:0,top:0,right:2,bottom:2},0xabcdef).unwrap();
        state.release_dc_lease(dc).unwrap();}
    assert_eq!(flush_one(||capture(&owner),|frame|{
        assert!(owner.try_lock().is_ok());assert_eq!(frame.header.hwnd,7);
        assert_eq!(&frame.payload[16+5*4..20+5*4],&0xffabcdefu32.to_le_bytes());true
    },|token,success|{assert_eq!(token.dc,backing);assert!(success);owner.lock().unwrap().finish_output(token,success);}),Ok(FlushOutcome::Presented));
    assert!(owner.lock().unwrap().pending_outputs().unwrap().is_empty());
    assert_eq!(flush_one(||capture(&owner),|_|panic!("clean output published"),|_,_|panic!("clean ACK")),Ok(FlushOutcome::Clean));
}
#[test]
fn font_queries_and_clipped_or_unchanged_pixels_never_trigger_output(){
    let (owner,_,dc)=setup();
    {let mut state=owner.lock().unwrap();assert!(state.pending_outputs().unwrap().is_empty());
        state.text_state(dc).unwrap();state.text_metrics(dc).unwrap();state.text_extent(dc,5).unwrap();
        state.fill_rect(dc,Rect{left:8,top:8,right:10,bottom:10},1).unwrap();
        state.fill_rect(dc,Rect{left:0,top:0,right:2,bottom:2},0).unwrap();}
    assert_eq!(flush_one(||capture(&owner),|_|panic!("query-only frame"),|_,_|panic!("query-only ACK")),Ok(FlushOutcome::Clean));
}
#[test]
fn failed_publication_keeps_canonical_damage_and_new_writes_survive_old_ack(){
    let (owner,_,dc)=setup();
    owner.lock().unwrap().fill_rect(dc,Rect{left:0,top:0,right:1,bottom:1},1).unwrap();
    assert_eq!(flush_one(||capture(&owner),|_|false,|token,success|{assert!(!success);owner.lock().unwrap().finish_output(token,success);}),Ok(FlushOutcome::Retry));
    assert_eq!(owner.lock().unwrap().pending_outputs().unwrap().len(),1);
    assert_eq!(flush_one(||capture(&owner),|_|{
        owner.try_lock().unwrap().fill_rect(dc,Rect{left:1,top:1,right:2,bottom:2},2).unwrap();true
    },|token,success|{assert!(success);owner.lock().unwrap().finish_output(token,success);}),Ok(FlushOutcome::Presented));
    assert_eq!(owner.lock().unwrap().pending_outputs().unwrap().len(),1);
    assert_eq!(flush_one(||capture(&owner),|_|true,|token,success|{assert!(success);owner.lock().unwrap().finish_output(token,success);}),Ok(FlushOutcome::Presented));
    assert!(owner.lock().unwrap().pending_outputs().unwrap().is_empty());
}
#[test]
fn concurrent_flusher_cannot_capture_same_backing_until_completion(){
    let (owner,_,dc)=setup();
    owner.lock().unwrap().write_dc_pixel(dc,0,0,1).unwrap();
    assert_eq!(flush_one(||capture(&owner),|_|{
        assert!(capture(&owner).unwrap().is_none());
        owner.lock().unwrap().write_dc_pixel(dc,1,1,2).unwrap();
        assert!(capture(&owner).unwrap().is_none());true
    },|token,success|{owner.lock().unwrap().finish_output(token,success);}),Ok(FlushOutcome::Presented));
    let (token,_)=capture(&owner).unwrap().expect("newer generation must remain flushable");
    owner.lock().unwrap().finish_output(token,true);
    assert!(owner.lock().unwrap().pending_outputs().unwrap().is_empty());
}
#[test]
fn serialization_failure_cancels_reservation_and_keeps_damage(){
    // Deliberately invalid transport HWND exercises capture failure after canonical reservation.
    let mut state=GdiManager::new();let dc=state.acquire_window_dc(0,1,1).unwrap();
    state.write_dc_pixel(dc,0,0,1).unwrap();let token=state.pending_output(0,dc).unwrap();
    assert!(reserve_snapshot(&mut state,token).is_err());
    assert_eq!(state.pending_output(0,dc),Some(token));assert!(state.reserve_output(token));
    state.finish_output(token,false);assert_eq!(state.pending_output(0,dc),Some(token));
}
#[test]
fn explicit_clean_zero_frame_reserves_then_acknowledges_and_failure_remains_pending(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,2,2).unwrap();
    assert!(g.pending_outputs().unwrap().is_empty());
    let prepared=prepare_explicit(&mut g,7,dc).unwrap();
    let prepared=reserve_prepared(&mut g,prepared).unwrap();
    let busy=prepare_explicit(&mut g,7,dc).unwrap();
    assert!(matches!(reserve_prepared(&mut g,busy),Err(PrepareError::Busy)));
    let status=publish_prepared(prepared,|record|{
        assert_eq!(&record.payload[16..20],&0xff000000u32.to_le_bytes());0
    },|token,success|{g.finish_output(token,success);});assert_eq!(status,0);
    // The busy explicit request may have advanced pending generation; finish it normally.
    let prepared=prepare_explicit(&mut g,7,dc).unwrap();
    let prepared=reserve_prepared(&mut g,prepared).unwrap();
    assert_eq!(publish_prepared(prepared,|_|0,|token,success|{g.finish_output(token,success);}),0);
    assert!(g.pending_outputs().unwrap().is_empty());
    let prepared=prepare_explicit(&mut g,7,dc).unwrap();
    let prepared=reserve_prepared(&mut g,prepared).unwrap();
    assert_eq!(publish_prepared(prepared,|_|0xc000000d,|token,success|{assert!(!success);g.finish_output(token,success);}),0xc000000d);
    let token=g.pending_output(7,dc).unwrap();assert!(g.reserve_output(token));g.finish_output(token,false);
}
#[test]
fn reserve_captured_reuses_record_allocation_and_validates_backing_identity_and_size(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,2,2).unwrap();
    let wrong=crate::nt_gdi_frame::snapshot(7,1,1,1,&[0]).unwrap();
    assert!(matches!(reserve_captured(&mut g,7,dc,wrong),Err(PrepareError::Invalid)));
    assert!(g.pending_outputs().unwrap().is_empty());
    let (w,h,pixels)=g.surface(dc).unwrap();let record=crate::nt_gdi_frame::snapshot(7,1,w,h,pixels).unwrap();
    let allocation=record.payload.as_ptr();
    let prepared=reserve_captured(&mut g,7,dc,record).unwrap();assert_eq!(prepared.record.payload.as_ptr(),allocation);
    let prepared=reserve_prepared(&mut g,prepared).unwrap();assert_eq!(prepared.record.payload.as_ptr(),allocation);
    assert_eq!(publish_prepared(prepared,|_|0,|token,success|{g.finish_output(token,success);}),0);
    assert!(g.pending_outputs().unwrap().is_empty());
}
