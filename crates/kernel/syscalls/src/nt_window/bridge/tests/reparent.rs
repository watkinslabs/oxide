use super::*;
#[test]
fn reparent_payload_uses_current_tree_parent_and_keeps_owner_distinct(){
    let mut state=WindowManager::new();let parent=state.create(17,None,0).unwrap();
    let child=state.create(17,Some(parent),0).unwrap();
    state.set_window_styles(child,ipc::win32_window::styles::WS_CHILD,0).unwrap();
    state.set_rect(child,WindowRect{left:100,top:120,right:120,bottom:140}).unwrap();
    state.set_parent(17,child,None).unwrap();
    let payload=reparent_payload(&state,child.raw() as u64).unwrap();
    let record=Record::new(Opcode::Reparent,1,child.raw() as u64,payload).unwrap();
    assert_eq!(wire::u64_at(&record.payload,0),Ok(0));
    assert_eq!(wire::Rect::decode_window(&record.payload[8..]).unwrap(),wire::Rect{x:100,y:120,width:20,height:20});
    let popup=state.create(17,None,0).unwrap();state.set_popup_owner(popup,Some(parent)).unwrap();
    state.set_rect(popup,WindowRect{left:1,top:2,right:3,bottom:4}).unwrap();
    let value=snapshot(&state,popup.raw() as u64).unwrap();
    assert_eq!(value.parent,parent.raw() as u64);
    assert_eq!(wire::u64_at(&reparent_payload(&state,popup.raw() as u64).unwrap(),0),Ok(0));
}
