use super::*;

#[test]
fn display_resize_runs_owner_callbacks_and_adopts_size_dependent_client_without_echo(){
    let _serial=SERIAL.lock().unwrap();let request=setup(5);
    let id=WindowId::from_raw(request.hwnd as u32).unwrap();
    let old=WindowRect{left:0,top:0,right:600,bottom:480};
    let next=WindowRect{left:10,top:20,right:310,bottom:500};
    let client=WindowRect{left:10,top:58,right:310,bottom:500};
    {
        let mut entries=GUI.lock();let e=&mut entries[0];
        e.state.set_rect(id,old).unwrap();
        e.state.set_client_rect(id,WindowRect{top:19,..old}).unwrap();
        e.state.set_visible(id,true).unwrap();
        assert!(position::queue_compositor(&mut e.state,&mut e.remote_positions,id,next));
        assert_eq!(e.state.rect(id),Some(old),"display worker must not apply geometry before callbacks");
    }
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=2);
    assert_eq!(position::pump_position_current(),None,"only the HWND owner consumes its position work");
    ENV.with(|e|{let mut e=e.borrow_mut();e.task.as_mut().unwrap().tid=1;e.allow_retrieval_resume=true;});
    assert_eq!(position::pump_position_current(),Some(STATUS_PENDING));
    ENV.with(|e|assert_eq!(e.borrow().callbacks[0].message,0x46));
    assert_eq!(complete(cb(0),0),STATUS_PENDING);
    ENV.with(|e|{let mut e=e.borrow_mut();let payload=&mut e.callbacks[1];assert_eq!(payload.message,0x83);
        for(i,n)in [client.left,client.top,client.right,client.bottom].into_iter().enumerate(){payload.bytes[i*4..i*4+4].copy_from_slice(&n.to_le_bytes());}
    });
    assert_eq!(complete(cb(1),0),STATUS_PENDING);
    assert_eq!(GUI.lock()[0].state.rect(id),Some(next));
    assert_eq!(GUI.lock()[0].state.client_rect_raw(id),Some(client));
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.callbacks[2].message,0x47);assert_eq!(e.publications,0,"accepted display geometry must not echo a configure");});
    assert_eq!(complete(cb(2),0),1);
    ENV.with(|e|assert_eq!(e.borrow().retrieval_resumes,1));
}

#[test]
fn queued_return_to_original_size_is_not_dropped_before_preceding_resize_commits(){
    let _serial=SERIAL.lock().unwrap();let request=setup(5);
    let id=WindowId::from_raw(request.hwnd as u32).unwrap();let old=request.rect;
    let resized=WindowRect{right:200,..old};
    {
        let mut entries=GUI.lock();let e=&mut entries[0];e.state.set_rect(id,old).unwrap();
        assert!(position::queue_compositor(&mut e.state,&mut e.remote_positions,id,resized));
        assert!(position::queue_compositor(&mut e.state,&mut e.remote_positions,id,old));
    }
    ENV.with(|e|e.borrow_mut().allow_retrieval_resume=true);
    for (offset,expected) in [(0,resized),(3,old)] {
        assert_eq!(position::pump_position_current(),Some(STATUS_PENDING));
        assert_eq!(complete(cb(offset),0),STATUS_PENDING);
        assert_eq!(complete(cb(offset+1),0),STATUS_PENDING);
        assert_eq!(complete(cb(offset+2),0),1);
        assert_eq!(GUI.lock()[0].state.rect(id),Some(expected));
    }
    assert_eq!(position::pump_position_current(),None);
    ENV.with(|e|assert_eq!(e.borrow().publications,0));
}

#[test]
fn application_adjustment_of_display_resize_publishes_corrected_geometry(){
    let _serial=SERIAL.lock().unwrap();let request=setup(5);
    let id=WindowId::from_raw(request.hwnd as u32).unwrap();
    {
        let mut entries=GUI.lock();let e=&mut entries[0];e.state.set_rect(id,request.rect).unwrap();
        assert!(position::queue_compositor(&mut e.state,&mut e.remote_positions,id,WindowRect{right:200,..request.rect}));
    }
    ENV.with(|e|e.borrow_mut().allow_retrieval_resume=true);
    assert_eq!(position::pump_position_current(),Some(STATUS_PENDING));
    ENV.with(|e|e.borrow_mut().callbacks[0].bytes[24..28].copy_from_slice(&150i32.to_le_bytes()));
    assert_eq!(complete(cb(0),0),STATUS_PENDING);
    assert_eq!(complete(cb(1),0),STATUS_PENDING);
    assert_eq!(complete(cb(2),0),1);
    assert_eq!(GUI.lock()[0].state.rect(id),Some(WindowRect{right:150,..request.rect}));
    ENV.with(|e|assert_eq!(e.borrow().publications,1,"application-adjusted geometry must reach the compositor"));
}

#[test]
fn nested_application_position_requires_display_correction_when_outer_callback_commits(){
    let _serial=SERIAL.lock().unwrap();let request=setup(5);
    let id=WindowId::from_raw(request.hwnd as u32).unwrap();
    {
        let mut entries=GUI.lock();let e=&mut entries[0];e.state.set_rect(id,request.rect).unwrap();
        assert!(position::queue_compositor(&mut e.state,&mut e.remote_positions,id,WindowRect{right:200,..request.rect}));
    }
    ENV.with(|e|e.borrow_mut().allow_retrieval_resume=true);
    assert_eq!(position::pump_position_current(),Some(STATUS_PENDING));
    let mut nested=request;nested.rect.right=150;
    assert_eq!(apply(nested,caller(99)),Outcome::Pending);
    assert_eq!(complete(cb(1),0),STATUS_PENDING);assert_eq!(complete(cb(2),0),99);
    assert_eq!(complete(cb(0),0),STATUS_PENDING);
    assert_eq!(complete(cb(3),0),STATUS_PENDING);assert_eq!(complete(cb(4),0),1);
    assert_eq!(GUI.lock()[0].state.rect(id),Some(WindowRect{right:200,..request.rect}));
    ENV.with(|e|assert_eq!(e.borrow().publications,2,"outer commit must correct the geometry published by its nested callback"));
}
