//! A real X server's exposure, through the production poll path: what the
//! retained surface can answer is answered here, and what it cannot becomes a
//! damage record the window itself must repaint.
use std::{io::{BufRead,Read,BufReader},process::{Child,Command,Stdio},os::unix::net::UnixStream,time::{Duration,Instant}};
use windows_compositor::{Backend,BridgeCommand,BridgeEvent,Frame,Rect,StreamTransport};
use syscall::nt_compositor::{self as wire,Opcode};
#[path="caret_repaint/xcb.rs"]mod xcb;

struct Server{child:Child,display:String}
impl Server{
    fn start()->Self{
        let mut child=Command::new("Xvfb").args(["-displayfd","1","-screen","0","320x240x24","-nolisten","tcp"])
            .env_remove("DISPLAY").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("Xvfb required for server damage boundary");
        let mut line=String::new();BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();assert!(!line.trim().is_empty());
        Self{child,display:format!(":{}",line.trim())}
    }
}
impl Drop for Server{fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();}}

fn create(backend:&mut Backend,hwnd:u32){backend.handle_command(BridgeCommand::Create{hwnd,title:Vec::new(),rect:Rect{left:0,top:0,right:4,bottom:3},parent:0,style:0x10000000,ex_style:0}).unwrap();}
fn frame(backend:&mut Backend,hwnd:u32,color:u32){
    backend.handle_command(BridgeCommand::Frame{hwnd,frame:Frame::new(4,3,4,vec![color;12],Rect{left:0,top:0,right:4,bottom:3}).unwrap()}).unwrap();
}
/// Drain until one damage record arrives, or fail; other events are not this
/// boundary's subject.
fn wait_damage(backend:&mut Backend)->BridgeEvent{
    let deadline=Instant::now()+Duration::from_secs(3);
    loop{
        while let Some(event)=backend.poll_event(){ if matches!(event,BridgeEvent::Damage{..}){return event;} }
        assert!(Instant::now()<deadline,"no damage record for an exposure the retained surface cannot answer");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn drain(backend:&mut Backend){for _ in 0..40{while backend.poll_event().is_some(){} std::thread::sleep(Duration::from_millis(1));}}

#[test]
fn an_exposure_the_retained_surface_cannot_answer_becomes_a_damage_record_on_the_wire(){
    let server=Server::start();let mut backend=Backend::connect(Some(&server.display)).unwrap();
    let client=xcb::Client::connect(&server.display);
    let (mut peer,stream)=UnixStream::pair().unwrap();let mut transport=StreamTransport::from_stream(stream).unwrap();
    create(&mut backend,7);let xid=backend.xid_for(7).unwrap();
    // Nothing has ever been presented for this window, so the backend holds no
    // pixels of its own to restore and the exposure belongs to the window. The
    // server states one the moment it maps the window.
    assert_eq!(wait_damage(&mut backend),BridgeEvent::Damage{hwnd:7,rect:Rect{left:0,top:0,right:4,bottom:3}});
    drain(&mut backend);
    // A sub-rectangle travels as itself, not as the whole window.
    client.expose(xid,1,0,2,3);
    assert_eq!(wait_damage(&mut backend),BridgeEvent::Damage{hwnd:7,rect:Rect{left:1,top:0,right:3,bottom:3}});
    // The same record reaches the kernel: production run_once sends it.
    client.expose(xid,0,1,4,2);
    let deadline=Instant::now()+Duration::from_secs(3);
    peer.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
    loop{
        assert!(Instant::now()<deadline,"damage record never reached the transport");
        backend.run_once(&mut transport).unwrap();
        let mut header=[0;wire::HEADER_LEN];if peer.read_exact(&mut header).is_err(){continue;}
        let header=wire::Header::decode(&header).unwrap();let mut payload=vec![0;header.length as usize];peer.read_exact(&mut payload).unwrap();
        if header.opcode!=Opcode::Damage{continue;}
        assert_eq!(header.hwnd,7);
        assert_eq!(wire::Rect::decode(&payload).unwrap(),wire::Rect{x:0,y:1,width:4,height:2});
        break;
    }
}

#[test]
fn an_exposure_the_retained_surface_answers_repaints_from_it_and_asks_the_window_for_nothing(){
    let server=Server::start();let mut backend=Backend::connect(Some(&server.display)).unwrap();
    let client=xcb::Client::connect(&server.display);
    create(&mut backend,7);let xid=backend.xid_for(7).unwrap();frame(&mut backend,7,0x112233);
    drain(&mut backend);
    client.clear(xid,4,3);
    assert_ne!(client.pixels(xid,4,3),vec![0x112233;12]);
    client.expose(xid,0,0,4,3);
    let deadline=Instant::now()+Duration::from_secs(3);
    loop{
        while let Some(event)=backend.poll_event(){
            assert!(!matches!(event,BridgeEvent::Damage{..}),"the retained surface answered this exposure; the window owes no paint");
        }
        if client.pixels(xid,4,3)==vec![0x112233;12]{break;}
        assert!(Instant::now()<deadline,"the retained surface never restored the exposed pixels");
        std::thread::sleep(Duration::from_millis(1));
    }
    // A window whose extent no longer matches its surface has no copy to
    // restore from, so the exposure becomes the window's paint again.
    backend.handle_command(BridgeCommand::Configure{hwnd:7,rect:Rect{left:0,top:0,right:8,bottom:6}}).unwrap();
    drain(&mut backend);
    client.expose(xid,0,0,8,6);
    assert_eq!(wait_damage(&mut backend),BridgeEvent::Damage{hwnd:7,rect:Rect{left:0,top:0,right:8,bottom:6}});
}
