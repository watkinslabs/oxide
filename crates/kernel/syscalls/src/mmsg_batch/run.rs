// The `recvmmsg` batch, composed. `super`'s rules answer one question each;
// this is the order they are asked in, which is itself part of the Linux
// contract — a malformed timeout outranks a bad descriptor, a pending error
// outranks the whole batch, and a failure after a delivery is reported as a
// count rather than an errno.
//
// Ungated on purpose, and the ONLY composition: the slot file
// (`299_recvmmsg.rs`) implements [`BatchOps`] and calls [`run`]. Before this
// the loop lived in that target-gated file and the hosted tests re-implemented
// it, so the tests proved a copy matched Linux, not the kernel.
//
// Each [`BatchOps`] method does one mechanical ABI step — read user memory,
// resolve a descriptor, run one receive — and reports a negative errno. It
// decides nothing.

use syscall::errno::Errno;

use crate::msg_layout::{EntryAbi, MsgLayout, entry_layout};

use super::{AfterDelivery, OnFailure, after_delivery, batch_len,
    copies_timeout_back, entry_flags, on_failure, reports_pending_error};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// ABI steps one batch needs from its caller.
pub trait BatchOps {
    /// Adopt the message layout the entry settled on. Every offset, stride and
    /// width this batch reads or writes follows from it; nothing below re-reads
    /// a flag to pick a shape. # C: O(1)
    fn use_layout(&mut self, layout: MsgLayout);
    /// Read and validate the caller's supplied timeout, if any. # C: O(1)
    fn import_timeout(&mut self) -> Result<(), i64>;
    /// Resolve and pin the one socket the whole batch receives from. # C: O(1)
    fn resolve(&mut self) -> Result<(), i64>;
    /// Consume the socket's pending error, 0 when there is none. # C: O(1)
    fn take_pending_error(&mut self) -> i32;
    /// Import entry `index` and run one receive with `flags`. # C: O(message)
    fn receive(&mut self, index: u64, flags: u64) -> i64;
    /// Publish one delivered length into entry `index`. # C: O(1)
    fn publish(&mut self, index: u64, len: i64) -> Result<(), i64>;
    /// Whether the message just delivered into `index` carried urgent data.
    /// # C: O(1)
    fn received_oob(&mut self, index: u64) -> bool;
    /// Nanoseconds left of the supplied timeout; `None` when none was
    /// supplied. # C: O(1)
    fn timeout_left(&mut self) -> Option<u64>;
    /// Store one errno as the socket's pending error. # C: O(1)
    fn latch_error(&mut self, errno: i32);
    /// Write the remaining timeout back to the caller. # C: O(1)
    fn copy_timeout_back(&mut self) -> Result<(), i64>;
}

/// Apply the failure rule to one failed entry, latching where it says to.
/// # C: O(1)
fn failed<O: BatchOps>(ops: &mut O, delivered: i64, failure: i64) -> i64 {
    match on_failure(delivered, failure) {
        OnFailure::Report(failure) => failure,
        OnFailure::Deliver { count, latch } => {
            if let Some(errno) = latch { ops.latch_error(errno); }
            count
        }
    }
}

/// One `recvmmsg` batch: the delivered count, or a negative errno when
/// nothing was delivered. `abi` is which entry point the call arrived through,
/// which with `flags` settles the layout — the first question asked, ahead of
/// the timeout, the descriptor and every entry. # C: O(vlen)
pub fn run<O: BatchOps>(ops: &mut O, flags: u64, vlen: u64, abi: EntryAbi) -> i64 {
    match entry_layout(flags, abi) {
        Ok(layout) => ops.use_layout(layout),
        Err(e) => return err(e),
    }
    if let Err(e) = ops.import_timeout() { return e; }
    if let Err(e) = ops.resolve() { return e; }
    if reports_pending_error(flags) {
        let pending = ops.take_pending_error();
        if pending != 0 { return -(pending as i64); }
    }
    let len = batch_len(vlen);
    let mut delivered: i64 = 0;
    let result = 'batch: {
        for index in 0..len {
            let got = ops.receive(index, entry_flags(flags, delivered as u64));
            if got < 0 { break 'batch failed(ops, delivered, got); }
            if let Err(e) = ops.publish(index, got) { break 'batch failed(ops, delivered, e); }
            delivered += 1;
            match after_delivery(ops.timeout_left(), ops.received_oob(index)) {
                AfterDelivery::Continue => {}
                AfterDelivery::TimedOut | AfterDelivery::OutOfBand => break,
            }
        }
        delivered
    };
    if copies_timeout_back(result) {
        if let Err(e) = ops.copy_timeout_back() { return e; }
    }
    result
}
