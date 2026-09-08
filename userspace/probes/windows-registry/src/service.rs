//! Bounded persistent clients sharing one canonical registry transaction owner.
use std::{io, num::NonZeroUsize, os::unix::net::{UnixListener, UnixStream},
    sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}, thread};
use crate::{RegistryStore, limits::LAZY_FLUSH_INTERVAL, wire};

#[derive(Clone, Copy, Debug)]
pub struct ServerLimits { pub max_clients: NonZeroUsize }

struct Permit { active: Arc<AtomicUsize> }
impl Permit {
    fn acquire(active: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        active.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |count| if count < limit { Some(count + 1) } else { None }).ok()?;
        Some(Self { active: Arc::clone(active) })
    }
}
impl Drop for Permit { fn drop(&mut self) { self.active.fetch_sub(1, Ordering::AcqRel); } }

/// Admit bounded persistent clients; database and sidecar remain one retained owner.
/// Socket admission errors propagate; excess clients are closed without registry success.
pub fn serve_listener(listener: UnixListener, store: RegistryStore, limits: ServerLimits) -> io::Result<()> {
    let store = Arc::new(Mutex::new(store));
    let active = Arc::new(AtomicUsize::new(0));
    spawn_lazy_writer(Arc::clone(&store))?;
    loop {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let Some(permit) = Permit::acquire(&active, limits.max_clients.get()) else {
            eprintln!("registry client rejected: active client limit reached");
            drop(stream); continue;
        };
        let owner = Arc::clone(&store);
        // Failed spawn drops the closure, releasing both accepted stream and admission permit.
        match thread::Builder::new().name("registry-client".into()).spawn(move || {
            let _permit = permit;
            if let Err(error) = serve_client(stream, &owner) { eprintln!("registry client failed: {error}"); }
        }) {
            Ok(worker) => drop(worker),
            Err(error) => eprintln!("registry client rejected: cannot create worker: {error}"),
        }
    }
}

fn serve_client(mut stream: UnixStream, owner: &Mutex<RegistryStore>) -> io::Result<()> {
    let served = wire::serve_requests(&mut stream, |request| {
        let mut store = locked(owner)?;
        wire::execute_request(&mut store, request)
    });
    // A departed client cannot ask for a flush, so its last mutations commit
    // here rather than waiting out the lazy interval.
    let committed = locked(owner).and_then(|mut store| wire::commit(&mut store));
    served?; committed
}

/// Write back mutations no client asked to flush, so an owner that is killed
/// loses at most one interval of sets rather than everything since its start.
fn spawn_lazy_writer(store: Arc<Mutex<RegistryStore>>) -> io::Result<()> {
    let worker = thread::Builder::new().name("registry-lazy-writer".into()).spawn(move || loop {
        thread::sleep(LAZY_FLUSH_INTERVAL);
        match locked(&store).and_then(|mut store| wire::commit(&mut store)) {
            Ok(()) => {}
            // A poisoned owner has no consistent state left to write back.
            Err(error) if error.kind() == io::ErrorKind::Other && store.is_poisoned() => {
                eprintln!("registry lazy write stopped: {error}"); return;
            }
            Err(error) => eprintln!("registry lazy write failed: {error}"),
        }
    })?;
    drop(worker);
    Ok(())
}

fn locked(owner: &Mutex<RegistryStore>) -> io::Result<std::sync::MutexGuard<'_, RegistryStore>> {
    owner.lock().map_err(|_| io::Error::other("registry owner poisoned"))
}

#[cfg(test)]
#[path = "service/tests.rs"]
mod tests;
