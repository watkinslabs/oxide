//! Production completion policy against real canonical paint sessions and GDI objects.
use crate::paint_prepare::{Prepared,Owner,finish,whole_window_covered};
use ipc::win32_window::{WindowManager,WindowId,WindowRect,WindowPosition};
use ipc::win32_gdi::GdiManager;
struct State{windows:WindowManager,gdi:GdiManager,copy_fault:bool,copies:Vec<Vec<u8>>}
impl Owner for State{
    fn commit(&mut self,p:Prepared,erase:bool)->Option<WindowRect>{
        let id=WindowId::from_raw(p.hwnd)?;
        if self.windows.get(id)?.owner_tid!=p.tid{return None;}
        self.windows.validate_paint_session(id,p.dc).ok()?;
        self.windows.finish_paint_erase(id,p.dc,erase).ok()?;
        self.windows.paint_rect(id).ok()
    }
    fn copy(&mut self,_:u64,bytes:&[u8])->bool{self.copies.push(bytes.to_vec());!self.copy_fault}
    fn retain(&mut self,_:Prepared)->bool{true}
    fn abort(&mut self,p:Prepared){if let Some(id)=WindowId::from_raw(p.hwnd){let _=self.windows.end_paint_session(id,p.dc);}}
    fn delete(&mut self,handle:u32){let _=self.gdi.delete_object(handle);}
}
fn rect(n:i32)->WindowRect{WindowRect{left:n,top:n,right:n+2,bottom:n+2}}
#[test]fn whole_window_sentinel_requires_exact_coverage_not_equal_bounds(){
    use ipc::win32_window::PaintRegion;
    let bounds=WindowRect{left:0,top:0,right:10,bottom:10};
    let full=PaintRegion::from_rect(bounds).unwrap();assert!(whole_window_covered(&full,bounds));
    let mut hole=full.try_copy().unwrap();hole.subtract(&PaintRegion::from_rect(rect(4)).unwrap()).unwrap();
    assert_eq!(hole.bounds(),Some(bounds));assert!(!whole_window_covered(&hole,bounds));
    assert!(!whole_window_covered(&PaintRegion::default(),bounds));
    assert!(!whole_window_covered(&full,WindowRect{left:0,top:0,right:0,bottom:10}));
}
fn setup()->(State,Prepared,WindowId){
    let mut windows=WindowManager::new();let id=windows.create(7,None,0).unwrap();
    windows.apply_position(7,WindowPosition{window:id,rect:WindowRect{left:0,top:0,right:10,bottom:10},client:None,order:None,visible:None,flags:0x10,notify_geometry:false}).unwrap();
    windows.invalidate(id,Some(rect(0))).unwrap();windows.begin_paint(id).unwrap();
    let mut gdi=GdiManager::new();let dc=gdi.create_dc(10,10).unwrap();windows.bind_paint_dc(id,dc).unwrap();
    (State{windows,gdi,copy_fault:false,copies:Vec::new()},Prepared{hwnd:id.raw(),dc,destination:4096,nc_region:1,tid:7},id)
}
#[test]fn callback_reinvalidation_survives_failed_preparation_and_real_dc_is_deleted(){
    for copy_fault in [false,true]{
        let (mut state,p,id)=setup();state.windows.invalidate(id,Some(rect(7))).unwrap();state.copy_fault=copy_fault;
        assert_eq!(finish(&mut state,p,if copy_fault{Ok(false)}else{Err(())}),0);
        assert!(state.windows.paint_session(id).is_err());assert!(state.gdi.delete_object(p.dc).is_err());
        assert_eq!(state.windows.begin_paint(id).unwrap(),Some(rect(7)));
    }
}
#[test]fn success_retains_exact_session_dc_and_pending_damage_until_endpaint(){
    let (mut state,p,id)=setup();state.windows.invalidate(id,Some(rect(7))).unwrap();
    assert_eq!(finish(&mut state,p,Ok(true)),p.dc as u64);
    let session=state.windows.validate_paint_session(id,p.dc).unwrap();assert!(!session.erase);assert!(session.delayed_erase);assert_eq!(session.damage,Some(rect(0)));
    assert_eq!(u32::from_le_bytes(state.copies[0][8..12].try_into().unwrap()),1);
    state.windows.end_paint_session(id,p.dc).unwrap();state.gdi.delete_object(p.dc).unwrap();
    assert_eq!(state.windows.begin_paint(id).unwrap(),Some(rect(7)));
}
