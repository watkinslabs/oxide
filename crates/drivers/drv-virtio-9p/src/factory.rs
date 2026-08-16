// Publishing this transport into the `trans=` directory a 9P mount resolves
// against. The filesystem never names this crate; it asks for `trans=virtio`
// and the factory registered here answers.

extern crate alloc;
use alloc::sync::Arc;

use ninep::err::{NpError, NpResult};
use ninep::opts::{MountOpts, Trans};
use ninep::transport::{registry, TransportRef};

use crate::transport::Virtio9pTransport;

/// `ENODEV` — no virtio-9p device carries the tag the mount named. Distinct
/// from a tag that exists and is already mounted, which is `EBUSY`: a caller
/// that mistyped a tag and one that mounted it twice need different answers.
const ERR_NO_SUCH_TAG: i32 = 19;
/// `EBUSY` — the tag exists but a mount already holds the device.
const ERR_TAG_IN_USE: i32 = 16;

fn open(opts: &MountOpts) -> NpResult<TransportRef> {
    if let Some(t) = Virtio9pTransport::claim(&opts.source) {
        return Ok(t as TransportRef);
    }
    let exists = crate::registry::tags().iter().any(|t| *t == opts.source);
    Err(NpError::Server(if exists { ERR_TAG_IN_USE } else { ERR_NO_SUCH_TAG }))
}

/// Publish `trans=virtio`. Idempotent, so calling it again after a device is
/// rebound replaces the entry rather than adding a second one. # C: O(1)
pub fn register_transport() { registry::register(Trans::Virtio, open); }

/// Withdraw `trans=virtio`, so a mount naming it fails instead of reaching a
/// driver that is going away. # C: O(1)
pub fn unregister_transport() { registry::unregister(Trans::Virtio); }

/// A transport for `tag` without going through the directory, for a caller
/// that already knows which device it wants. # C: O(N_devices)
pub fn open_tag(tag: &str) -> Option<Arc<Virtio9pTransport>> { Virtio9pTransport::claim(tag) }
