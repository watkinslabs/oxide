use std::env;
use std::time::Duration;

/// Milliseconds since this process started, for startup measurements.
fn elapsed_ms(start: std::time::Instant) -> u128 { start.elapsed().as_millis() }

fn main() {
    let start = std::time::Instant::now();
    let args: Vec<String> = env::args().skip(1).collect();
    let Ok(options) = windows_compositor::parse_args(&args) else {
        eprintln!("usage: windows-compositor --fd 0 [--ready-fd <n>]");
        std::process::exit(2);
    };
    let display = env::var("DISPLAY").ok();
    // The bridge handshake is bounded, and this startup does a series of
    // synchronous X round trips. Whether it is slow or stuck is the difference
    // between a real hang and a deadline that does not fit the guest, and only
    // a measurement tells them apart.
    let mut backend = match windows_compositor::Backend::connect(display.as_deref()) { Ok(backend) => backend, Err(_) => { eprintln!("windows-compositor: X11/XWayland display connection or XKB initialization failed after {}ms", elapsed_ms(start)); std::process::exit(1); } };
    eprintln!("windows-compositor: display connected after {}ms", elapsed_ms(start));
    let mut transport = match windows_compositor::StreamTransport::from_fd0() { Ok(transport) => transport, Err(_) => { eprintln!("windows-compositor: inherited transport unavailable"); std::process::exit(1); } };
    // The bridge handshake completes only once the monitor snapshot arrives, so
    // failing to send one is a startup failure, not something to continue past:
    // swallowing it left the caller waiting out its whole handshake window with
    // nothing on stderr to say why.
    let Some(snapshot) = backend.monitor_snapshot() else {
        eprintln!("windows-compositor: display reports no usable screen geometry");
        std::process::exit(1);
    };
    // Readiness is signalled only after the snapshot is queued on the bridge, so
    // the launcher's bind observes data already written instead of racing X.
    if let Err(error) = windows_compositor::publish_then_notify(&mut transport, snapshot, options.ready_fd) {
        eprintln!("windows-compositor: cannot publish monitor geometry after {}ms: {error:?}", elapsed_ms(start));
        std::process::exit(1);
    }
    eprintln!("windows-compositor: monitor geometry published after {}ms", elapsed_ms(start));
    loop { match backend.run_once(&mut transport) { Ok(true) => {}, Ok(false) => std::thread::sleep(Duration::from_millis(1)), Err(error) => { eprintln!("windows-compositor: {error:?}"); break; } } }
}
