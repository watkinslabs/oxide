//! Native Linux registry service endpoint for future Win32 adapters.

use std::env;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;

use windows_registry::{serve_connection, RegistryStore};

fn main() -> ExitCode {
    let mut args = env::args_os(); let _program = args.next();
    let Some(socket) = args.next() else { usage(); return ExitCode::from(2); };
    let Some(database) = args.next() else { usage(); return ExitCode::from(2); };
    let socket = PathBuf::from(socket); let database = PathBuf::from(database);
    let mut store = match RegistryStore::open(&database) { Ok(store) => store, Err(error) => { eprintln!("cannot open registry: {error:?}"); return ExitCode::from(1); } };
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) { Ok(listener) => listener, Err(error) => { eprintln!("cannot bind registry socket: {error}"); return ExitCode::from(1); } };
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => { if let Err(error) = serve_connection(&mut stream, &mut store) { eprintln!("registry client disconnected: {error}"); } if let Err(error) = store.flush() { eprintln!("cannot flush registry: {error:?}"); return ExitCode::from(1); } }
            Err(error) => { eprintln!("registry accept failed: {error}"); return ExitCode::from(1); }
        }
    }
    ExitCode::SUCCESS
}

fn usage() { eprintln!("usage: registryd <unix-socket> <database>"); }
