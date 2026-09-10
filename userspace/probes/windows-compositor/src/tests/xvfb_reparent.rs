//! A dropdown detached from its control must escape the old native clip.
use std::{os::unix::net::UnixStream,ptr};
use crate::{Backend,BridgeCommand,Frame,Rect,StreamTransport,ffi};
use crate::xvfb_harness::{xvfb,connect,send,ack,child_order};
use syscall::nt_compositor::{self as wire,Opcode};

#[test]
fn combo_list_reparents_on_the_wire_and_keeps_its_drawable(){
    let server=xvfb();let mut backend=Backend::connect(Some(&server.display)).unwrap();
    let (mut peer,stream)=UnixStream::pair().unwrap();let mut transport=StreamTransport::from_stream(stream).unwrap();
    let (conn,root)=unsafe{connect(&server.display)};
    let rect=Rect{left:5,top:5,right:25,bottom:25};
    for (hwnd,parent,style) in [(1,0,0),(2,1,crate::styles::WS_CHILD)]{
        backend.handle_command(BridgeCommand::Create{hwnd,parent,style,ex_style:0,title:vec![],rect}).unwrap();
        backend.handle_command(BridgeCommand::Show{hwnd}).unwrap();
    }
    let xid=backend.xid_for(2).unwrap();let parent=backend.xid_for(1).unwrap();
    assert!(unsafe{child_order(conn,parent)}.contains(&xid));
    let damage=Rect{left:0,top:0,right:20,bottom:20};
    backend.handle_command(BridgeCommand::Frame{hwnd:2,frame:Frame::new(20,20,20,vec![0x00123456;400],damage).unwrap()}).unwrap();
    let mut payload=0u64.to_le_bytes().to_vec();
    payload.extend_from_slice(&wire::Rect{x:100,y:100,width:20,height:20}.encode_window().unwrap());
    send(&mut peer,Opcode::Reparent,1,2,payload);ack(&mut peer,&mut backend,&mut transport,1);
    assert_eq!(backend.xid_for(2),Some(xid));
    assert!(unsafe{child_order(conn,root)}.contains(&xid));
    assert!(!unsafe{child_order(conn,parent)}.contains(&xid));
    unsafe{
        let cookie=ffi::xcb_get_image(conn,ffi::IMAGE_FORMAT_Z_PIXMAP,xid,1,1,1,1,u32::MAX);
        let mut error=ptr::null_mut();let reply=ffi::xcb_get_image_reply(conn,cookie,&mut error);
        assert!(!reply.is_null(),"detached list must be viewable outside former parent");
        assert_eq!(*(ffi::xcb_get_image_data(reply) as *const u32)&0x00ffffff,0x00123456);
        libc::free(reply.cast());
    }
    let mut payload=1u64.to_le_bytes().to_vec();
    payload.extend_from_slice(&wire::Rect{x:0,y:0,width:20,height:20}.encode_window().unwrap());
    send(&mut peer,Opcode::Reparent,2,2,payload);ack(&mut peer,&mut backend,&mut transport,2);
    assert!(unsafe{child_order(conn,parent)}.contains(&xid));
    assert_eq!(backend.xid_for(2),Some(xid));
    assert!(backend.handle_command(BridgeCommand::Reparent{hwnd:2,parent:99,rect}).is_err());
    assert!(unsafe{child_order(conn,parent)}.contains(&xid));
    unsafe{ffi::xcb_destroy_window(conn,xid);child_order(conn,parent);}
    assert!(backend.handle_command(BridgeCommand::Reparent{hwnd:2,parent:0,rect}).is_err(),"native rejection cannot be acknowledged");
    unsafe{ffi::xcb_disconnect(conn);}
}
