//! Native Linux registry service endpoint for future Win32 adapters.

use std::env;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::num::NonZeroUsize;

use windows_registry::{serve_listener, RegistryStore, ServerLimits};

const MAX_ACTIVE_CLIENTS: NonZeroUsize = NonZeroUsize::new(128).unwrap();

fn main() -> ExitCode {
    let mut args = env::args_os(); let _program = args.next();
    let Some(socket) = args.next() else { usage(); return ExitCode::from(2); };
    let Some(database) = args.next() else { usage(); return ExitCode::from(2); };
    let socket = PathBuf::from(socket); let database = PathBuf::from(database);
    let store = match RegistryStore::open_exclusive(&database) {
        Ok(store) => store,
        // One service per user database. A second launch is a normal outcome:
        // the shared service is already up and owns the live socket.
        Err(windows_registry::Error::AlreadyServing) => {
            eprintln!("registryd: already serving {}", database.display());
            return ExitCode::SUCCESS;
        }
        Err(error) => { eprintln!("cannot open registry: {error:?}"); return ExitCode::from(1); }
    };
    // Only the service that owns the database lock may replace the socket, so
    // this can never unlink an endpoint another service is still serving.
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) { Ok(listener) => listener, Err(error) => { eprintln!("cannot bind registry socket: {error}"); return ExitCode::from(1); } };
    match serve_listener(listener, store, ServerLimits { max_clients: MAX_ACTIVE_CLIENTS }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("registry listener failed: {error}"); ExitCode::from(1) }
    }
}

fn usage() { eprintln!("usage: registryd <unix-socket> <database>"); }
