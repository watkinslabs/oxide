// The transport directory a mount resolves `trans=` against.
//
// A transport lives in the crate that owns its device — the virtio one in a
// driver crate, a socket one in the network stack — and registers itself here.
// The filesystem then asks for a transport BY NAME and never depends on any of
// them, which is what keeps a kernel filesystem crate from depending on a
// driver crate to open a mount.

extern crate alloc;
use alloc::vec::Vec;

use sync::{Spinlock, Tty as NpClass};

use crate::err::{NpError, NpResult};
use crate::opts::{MountOpts, Trans};
use super::TransportRef;

/// Build a transport for one mount. Fails when the named device does not
/// exist, is already mounted, or cannot be opened.
pub type TransportFactory = fn(&MountOpts) -> NpResult<TransportRef>;

static FACTORIES: Spinlock<Vec<(Trans, TransportFactory)>, NpClass> = Spinlock::new(Vec::new());

/// Publish `factory` as the implementation of `trans`. Registering a second
/// factory for the same transport REPLACES the first rather than adding a
/// parallel one: two factories for one name is a second source of truth about
/// which device a mount reaches. # C: O(N)
pub fn register(trans: Trans, factory: TransportFactory) {
    let mut g = FACTORIES.lock();
    if let Some(slot) = g.iter_mut().find(|(t, _)| *t == trans) { slot.1 = factory; return; }
    g.push((trans, factory));
}

/// Withdraw a transport, so a mount naming it fails instead of reaching a
/// module that is going away. # C: O(N)
pub fn unregister(trans: Trans) { FACTORIES.lock().retain(|(t, _)| *t != trans); }

/// Transports currently available. # C: O(N)
pub fn available() -> Vec<Trans> { FACTORIES.lock().iter().map(|(t, _)| *t).collect() }

/// Build the transport a mount asked for. `Enoprotoopt` when nothing
/// implements it — distinct from the device being absent, which the factory
/// itself reports. # C: O(N) + factory
pub fn open(opts: &MountOpts) -> NpResult<TransportRef> {
    let factory = FACTORIES.lock().iter().find(|(t, _)| *t == opts.trans).map(|(_, f)| *f);
    match factory {
        Some(f) => f(opts),
        None => Err(NpError::Server(92)),
    }
}
