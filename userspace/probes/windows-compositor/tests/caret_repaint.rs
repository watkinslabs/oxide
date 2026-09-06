//! Real backend/protocol/repaint boundary under Xvfb; not a GNOME acceptance claim.
use std::{io::{BufRead,BufReader,Read,Write},os::unix::net::UnixStream,process::{Child,Command,Stdio},time::{Duration,Instant}};
use windows_compositor::{Backend,BridgeCommand,Frame,Rect,StreamTransport};
use syscall::nt_compositor::{self as wire,caret::Snapshot,Opcode,Record};
#[path="caret_repaint/xcb.rs"]mod xcb;
struct Server{child:Child,display:String}
impl Server{
    fn start()->Self{
        let mut child=Command::new("Xvfb").args(["-displayfd","1","-screen","0","320x240x24","-nolisten","tcp"])
            .env_remove("DISPLAY").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("Xvfb required for caret repaint boundary");
        let mut line=String::new();BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();assert!(!line.trim().is_empty());
        Self{child,display:format!(":{}",line.trim())}
    }
}
impl Drop for Server{fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();}}
fn create(backend:&mut Backend,hwnd:u32){backend.handle_command(BridgeCommand::Create{hwnd,title:Vec::new(),rect:Rect{left:0,top:0,right:4,bottom:3},parent:0,style:0x10000000,ex_style:0}).unwrap();}
fn frame(backend:&mut Backend,hwnd:u32,color:u32){
    let mut pixels=vec![color;18];for index in [4,5,10,11,16,17]{pixels[index]=0xdeadbeef;}
    backend.handle_command(BridgeCommand::Frame{hwnd,frame:Frame::new(4,3,6,pixels,Rect{left:0,top:0,right:4,bottom:3}).unwrap()}).unwrap();
}
fn snapshot(generation:u64,x:i32,y:i32,visible:bool)->Snapshot{Snapshot::solid(generation,wire::Rect{x,y,width:1,height:2},visible).unwrap()}
fn caret(backend:&mut Backend,transport:&mut StreamTransport,peer:&mut UnixStream,sequence:u64,hwnd:u64,snapshot:Snapshot)->u32{
    peer.write_all(&Record::new(Opcode::Caret,sequence,hwnd,snapshot.encode().unwrap()).unwrap().encode().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(5))).unwrap();let deadline=Instant::now()+Duration::from_secs(3);
    loop{
        assert!(Instant::now()<deadline,"caret ACK timeout");backend.run_once(transport).unwrap();
        let mut header=[0;wire::HEADER_LEN];if peer.read_exact(&mut header).is_err(){continue;}
        let header=wire::Header::decode(&header).unwrap();let mut payload=vec![0;header.length as usize];peer.read_exact(&mut payload).unwrap();
        if header.opcode==Opcode::Ack&&header.sequence==sequence{return wire::u32_at(&payload,0).unwrap();}
    }
}
fn wait_pixels(backend:&mut Backend,client:&xcb::Client,xid:u32,expected:&[u32]){
    let deadline=Instant::now()+Duration::from_secs(3);
    loop{backend.poll_event();let pixels=client.pixels(xid,4,3);if pixels==expected{return;}
        assert!(Instant::now()<deadline,"server pixels mismatch: {pixels:x?} != {expected:x?}");std::thread::sleep(Duration::from_millis(1));}
}
#[test]
fn real_repaint_composites_caret_on_expose_and_restores_move_hide_and_new_frame(){
    let server=Server::start();let mut backend=Backend::connect(Some(&server.display)).unwrap();let client=xcb::Client::connect(&server.display);
    let (mut peer,stream)=UnixStream::pair().unwrap();let mut transport=StreamTransport::from_stream(stream).unwrap();
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,1,7,snapshot(1,1,0,true)),1,"unknown HWND must reject before allocating presentation state");
    create(&mut backend,7);frame(&mut backend,7,0x112233);let xid=backend.xid_for(7).unwrap();
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,2,7,snapshot(1,1,0,true)),0);
    let mut expected=vec![0x112233;12];expected[1]^=0xffffff;expected[5]^=0xffffff;wait_pixels(&mut backend,&client,xid,&expected);
    // Remove server pixels without changing the retained frame. A synthetic
    // Expose must restore only its rectangle through production poll/repaint.
    for _ in 0..2{
        for _ in 0..20{backend.poll_event();}client.clear(xid,4,3);let mut damaged=client.pixels(xid,4,3);
        assert_ne!(damaged,expected);client.expose(xid,1,0,1,2);damaged[1]=expected[1];damaged[5]=expected[5];
        wait_pixels(&mut backend,&client,xid,&damaged);
    }
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,3,7,snapshot(2,2,1,true)),0);
    expected=vec![0x112233;12];expected[6]^=0xffffff;expected[10]^=0xffffff;wait_pixels(&mut backend,&client,xid,&expected);
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,4,7,snapshot(3,2,1,false)),0);wait_pixels(&mut backend,&client,xid,&vec![0x112233;12]);
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,5,7,snapshot(4,2,1,true)),0);frame(&mut backend,7,0xabcdef);
    expected=vec![0xabcdef;12];expected[6]^=0xffffff;expected[10]^=0xffffff;wait_pixels(&mut backend,&client,xid,&expected);
    backend.handle_command(BridgeCommand::Destroy{hwnd:7}).unwrap();
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,6,7,snapshot(5,0,0,true)),1);assert_eq!(backend.xid_for(7),None);
}
#[test]
fn caret_before_first_frame_is_applied_to_real_frame_and_stale_generation_cannot_undo_hide(){
    let server=Server::start();let mut backend=Backend::connect(Some(&server.display)).unwrap();let client=xcb::Client::connect(&server.display);
    let (mut peer,stream)=UnixStream::pair().unwrap();let mut transport=StreamTransport::from_stream(stream).unwrap();create(&mut backend,9);
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,1,9,snapshot(10,0,0,true)),0);frame(&mut backend,9,0x654321);
    let xid=backend.xid_for(9).unwrap();let mut expected=vec![0x654321;12];expected[0]^=0xffffff;expected[4]^=0xffffff;wait_pixels(&mut backend,&client,xid,&expected);
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,2,9,snapshot(11,0,0,false)),0);
    assert_eq!(caret(&mut backend,&mut transport,&mut peer,3,9,snapshot(10,0,0,true)),0);wait_pixels(&mut backend,&client,xid,&vec![0x654321;12]);
}
