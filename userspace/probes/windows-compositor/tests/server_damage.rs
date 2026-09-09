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
fn parent_surface_pixels_are_visible_through_a_child_control_window() {
    const WS_CHILD:u32=0x40000000;
    const WS_VISIBLE:u32=0x10000000;
    let server=Server::start();let mut backend=Backend::connect(Some(&server.display)).unwrap();
    let client=xcb::Client::connect(&server.display);
    create(&mut backend,7);frame(&mut backend,7,0x112233);
    backend.handle_command(BridgeCommand::Create{hwnd:8,title:Vec::new(),
        rect:Rect{left:1,top:1,right:3,bottom:3},parent:7,style:WS_CHILD|WS_VISIBLE,ex_style:0}).unwrap();
    let child=backend.xid_for(8).unwrap();
    backend.handle_command(BridgeCommand::Frame{hwnd:8,
        frame:Frame::new(2,2,2,vec![0xabcdef;4],Rect{left:0,top:0,right:2,bottom:2}).unwrap()}).unwrap();
    drain(&mut backend);
    assert_eq!(client.pixels(child,2,2),vec![0xabcdef;4]);
    // A parent-clipped control DC publishes its label into the parent
    // backing. The native child window must not clip that label away.
    backend.handle_command(BridgeCommand::Frame{hwnd:7,
        frame:Frame::new(4,3,1,vec![0x445566;2],Rect{left:1,top:1,right:2,bottom:3}).unwrap()}).unwrap();
    let deadline=Instant::now()+Duration::from_secs(2);
    loop {
        let pixels=client.pixels(child,2,2);
        if pixels==vec![0x445566,0xabcdef,0x445566,0xabcdef]{break;}
        assert!(Instant::now()<deadline,"parent drawing was clipped out of child control: {pixels:x?}");
        backend.poll_event();std::thread::sleep(Duration::from_millis(1));
    }
}

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

/// A surface holds only what has been presented into it. Storage for the
/// window exists from the moment the surface is allocated, but the pixels a
/// frame has never covered are the window's own: putting the colour of empty
/// storage over them on an exposure paints away content this backend never
/// saw, and leaves the display holding a picture the surface disagrees with.
/// So an exposure reaching past what the surface holds is the window's paint,
/// exactly as it is for a window that has never presented at all.
#[test]
fn an_exposure_past_what_a_partial_frame_covered_is_the_windows_paint(){
    let server=Server::start();let mut backend=Backend::connect(Some(&server.display)).unwrap();
    let client=xcb::Client::connect(&server.display);
    create(&mut backend,7);let xid=backend.xid_for(7).unwrap();
    // One frame covering the left half of a four-by-three window.
    backend.handle_command(BridgeCommand::Frame{hwnd:7,frame:Frame::new(4,3,2,vec![0x112233;6],Rect{left:0,top:0,right:2,bottom:3}).unwrap()}).unwrap();
    drain(&mut backend);
    // Inside the covered half the surface answers, and the window owes nothing.
    client.clear(xid,4,3);
    client.expose(xid,0,0,2,3);
    let deadline=Instant::now()+Duration::from_secs(3);
    loop{
        while let Some(event)=backend.poll_event(){
            assert!(!matches!(event,BridgeEvent::Damage{..}),"the surface holds these pixels and owes the window no paint");
        }
        if client.pixels(xid,2,3)==vec![0x112233;6]{break;}
        assert!(Instant::now()<deadline,"the retained surface never restored the pixels it holds");
        std::thread::sleep(Duration::from_millis(1));
    }
    drain(&mut backend);
    // The half no frame ever covered is the window's, and travels as damage.
    client.expose(xid,2,0,2,3);
    assert_eq!(wait_damage(&mut backend),BridgeEvent::Damage{hwnd:7,rect:Rect{left:2,top:0,right:4,bottom:3}});
    // An exposure straddling both is the window's too: half of it cannot be
    // answered, and a window repainting a superset of its damage is normal.
    drain(&mut backend);
    client.expose(xid,0,0,4,3);
    assert_eq!(wait_damage(&mut backend),BridgeEvent::Damage{hwnd:7,rect:Rect{left:0,top:0,right:4,bottom:3}});
}
