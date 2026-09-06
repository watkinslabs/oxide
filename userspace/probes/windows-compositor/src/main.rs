use std::env;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "--fd" || args[2] != "0" { eprintln!("usage: windows-compositor --fd 0"); std::process::exit(2); }
    let display = env::var("DISPLAY").ok();
    let mut backend = match windows_compositor::Backend::connect(display.as_deref()) { Ok(backend) => backend, Err(_) => { eprintln!("windows-compositor: X11/XWayland display connection or XKB initialization failed"); std::process::exit(1); } };
    let mut transport = match windows_compositor::StreamTransport::from_fd0() { Ok(transport) => transport, Err(_) => { eprintln!("windows-compositor: inherited transport unavailable"); std::process::exit(1); } };
    // The bridge handshake completes only once the monitor snapshot arrives, so
    // failing to send one is a startup failure, not something to continue past:
    // swallowing it left the caller waiting out its whole handshake window with
    // nothing on stderr to say why.
    let Some(snapshot) = backend.monitor_snapshot() else {
        eprintln!("windows-compositor: display reports no usable screen geometry");
        std::process::exit(1);
    };
    if let Err(error) = windows_compositor::NativeTransport::send(&mut transport, windows_compositor::BridgeEvent::WorkArea(snapshot)) {
        eprintln!("windows-compositor: cannot publish monitor geometry: {error:?}");
        std::process::exit(1);
    }
    loop { match backend.run_once(&mut transport) { Ok(true) => {}, Ok(false) => std::thread::sleep(Duration::from_millis(1)), Err(error) => { eprintln!("windows-compositor: {error:?}"); break; } } }
}
