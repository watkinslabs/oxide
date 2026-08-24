//! Link-layer control protocol handoff.

use sync::{Socket as SocketLockClass, Spinlock};

use crate::NetIfaceId;

type Handler = fn(NetIfaceId, &[u8]) -> bool;
static HANDLER: Spinlock<Option<Handler>, SocketLockClass> = Spinlock::new(None);

pub fn register(handler: Handler) -> bool {
    let mut current = HANDLER.lock();
    if current.is_some() { return false; }
    *current = Some(handler);
    true
}

pub(crate) fn dispatch(iface: NetIfaceId, frame: &[u8]) -> bool {
    let handler = *HANDLER.lock();
    handler.is_some_and(|handler| handler(iface, frame))
}
