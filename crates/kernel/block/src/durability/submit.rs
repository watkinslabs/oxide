//! Issuing the commands one durability promise decomposes into.
//!
//! One place, so the order is decided once. A submitter that sequenced its own
//! pre-flush would be one `if` away from issuing it after the write it was
//! meant to precede, and the resulting volume is only wrong after a power cut
//! — the one failure no test on the machine can see.

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::queue_limits::QueueFeatures;
use crate::types::KResult;

use super::{residue, sequence, Durability, Sequence};

/// What `dev` advertises about its cache, as the two facts the sequence needs.
///
/// A device whose topology cannot be read is treated as having a volatile
/// cache and no forced-unit-access, which is the conservative pair: it costs a
/// flush that may not have been needed and cannot drop one that was.
/// # C: O(1)
pub fn facts(dev: &dyn BlockDevice) -> (bool, bool) {
    match dev.queue_limits() {
        Ok(l) => (l.features().contains(QueueFeatures::WRITE_CACHE),
                  l.features().contains(QueueFeatures::FUA)),
        Err(_) => (true, false),
    }
}

/// Submit one request, keeping the durability promise it carries.
///
/// The pre-flush goes first and is waited for, then the data, then the
/// post-flush. Nothing here is optional or reorderable: the whole value of the
/// promise is that the caller can name a point at which the earlier writes are
/// on the medium.
/// # C: one or two device flushes plus the write
pub fn submit_durable(dev: &dyn BlockDevice, req: &mut BlockRequest) -> KResult<()> {
    let (cache, fua) = facts(dev);
    let has_data = req.len_blocks != 0;
    let seq = sequence(cache, fua, req.durability, has_data);
    run(dev, req, seq)
}

/// The same, against a sequence already decided.
///
/// Split out so a caller that has to decide the sequence from facts it holds
/// itself — a volume that spans several devices, say — runs the same issue
/// order as everyone else.
/// # C: one or two device flushes plus the write
pub fn run(dev: &dyn BlockDevice, req: &mut BlockRequest, seq: Sequence) -> KResult<()> {
    run_with(seq, || dev.flush(), |d| { req.durability = d; dev.submit_sync(req) })
}

/// The ORDER, over whatever a caller's flush and write happen to be.
///
/// The single owner of the sequence. A layer that wrote the three steps out
/// itself would be one edit away from issuing the pre-flush after the write it
/// exists to precede, and the result is a volume that is only wrong after a
/// power cut — which nothing on the running machine can observe. So every layer
/// that sequences a durability promise, whatever its own write path looks like,
/// comes through here.
///
/// Generic over the error so a filesystem's `Errno` path and the block layer's
/// own share the one implementation.
/// # C: the callbacks
pub fn run_with<E>(seq: Sequence,
                   mut flush: impl FnMut() -> Result<(), E>,
                   mut write: impl FnMut(Durability) -> Result<(), E>) -> Result<(), E> {
    if seq.preflush { flush()?; }
    if seq.data { write(residue(seq))?; }
    if seq.postflush { flush()?; }
    Ok(())
}

/// Make everything already written to `dev` durable on it — Linux
/// `blkdev_issue_flush`.
///
/// Expressed as an empty request carrying the pre-flush promise rather than as
/// a direct call, so a device with no volatile cache answers success without a
/// command through the same decision every other request uses.
/// # C: one device flush
pub fn issue_flush(dev: &dyn BlockDevice) -> KResult<()> {
    let mut req = BlockRequest::new_flush();
    req.durability = Durability::NONE | super::PREFLUSH;
    submit_durable(dev, &mut req)
}
