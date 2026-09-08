use alloc::{collections::VecDeque, vec::Vec};
use syscall::nt_compositor::{self as wire, Opcode, Record};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError { Invalid, Full, Disconnected, Unknown, NoMemory, Busy, Timeout }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion { Pending, Presented, Failed(u32) }
/// What one acknowledgement settled. A refusal is the desktop saying it did
/// not carry out the record it was handed, and for a drawing submission
/// nobody waits on that verdict: unless it is observed here it is observed
/// nowhere, and the window simply keeps its last pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settled { Presented, Carried, Refused { opcode: Opcode, status: u32 } }
pub(super) struct Prepared { bytes: Vec<u8>, hwnd: u64, opcode: Opcode }
struct Entry { sequence: u64, hwnd: u64, opcode: Opcode, charge: usize, bytes: Option<Vec<u8>>, result: Completion, sent: bool, ack: Option<u32>, awaited: bool }
pub struct Queue { entries: VecDeque<Entry>, bytes: usize, next: u64, dead: bool }

impl Prepared {
    pub(super) fn new(opcode: Opcode, hwnd: u64, payload: Vec<u8>) -> Result<Self, TransportError> {
        if opcode.from_backend() { return Err(TransportError::Invalid); }
        let bytes = Record::new(opcode, 1, hwnd, payload).and_then(|r| r.encode())
            .map_err(|error| if error == wire::Error::Allocation { TransportError::NoMemory } else { TransportError::Invalid })?;
        Ok(Self { bytes, hwnd, opcode })
    }
}

impl Queue {
    /// # C: O(1)
    pub const fn new() -> Self { Self { entries: VecDeque::new(), bytes: 0, next: 1, dead: false } }
    /// Reserve every queue slot before the binding is published. # C: O(records)
    pub fn try_new() -> Result<Self, TransportError> {
        let mut queue = Self::new();
        queue.entries.try_reserve_exact(wire::MAX_QUEUED_RECORDS).map_err(|_| TransportError::NoMemory)?;
        Ok(queue)
    }
    /// Payload copy and validation have already finished outside the queue lock.
    /// `awaited` records whether a caller will consume this record's completion:
    /// an unawaited one releases its slot the moment it settles, because no
    /// `take_completion` will ever come for it. # C: O(1)
    pub(super) fn enqueue_prepared(&mut self, prepared: &mut Option<Prepared>, awaited: bool) -> Result<u64, TransportError> {
        if self.dead { return Err(TransportError::Disconnected); }
        let charge = prepared.as_ref().ok_or(TransportError::Invalid)?.bytes.len();
        if self.entries.len() >= wire::MAX_QUEUED_RECORDS || charge > wire::MAX_QUEUED_BYTES.saturating_sub(self.bytes) { return Err(TransportError::Full); }
        let sequence = self.next;
        let next = sequence.checked_add(1).ok_or(TransportError::Full)?;
        self.entries.try_reserve(1).map_err(|_| TransportError::NoMemory)?;
        let Prepared { mut bytes, hwnd, opcode } = prepared.take().ok_or(TransportError::Invalid)?;
        bytes[16..24].copy_from_slice(&sequence.to_le_bytes());
        self.entries.push_back(Entry { sequence, hwnd, opcode, charge, bytes: Some(bytes), result: Completion::Pending, sent: false, ack: None, awaited });
        self.bytes += charge; self.next = next; Ok(sequence)
    }
    /// Hand the next unsent record to the socket, with the sequence its
    /// acknowledgement will carry. Records stream out back to back: the
    /// socket's own capacity is the flow control, and a record already in
    /// flight never stops the one behind it. Stopping until the desktop
    /// answered made every later record wait a whole application round trip,
    /// which is head-of-line blocking, not back pressure. # C: O(records)
    pub fn take_send(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.dead { return None; }
        let entry = self.entries.iter_mut().find(|e| e.bytes.is_some())?;
        let sequence = entry.sequence;
        entry.bytes.take().map(|bytes| (sequence, bytes))
    }
    /// Answers what the acknowledgement settled: pixels the desktop confirms
    /// it was handed, a control request it carried out, or a refusal.
    /// # C: O(records)
    pub fn acknowledge(&mut self, sequence: u64, hwnd: u64, status: u32) -> Result<Settled, TransportError> {
        if self.dead { return Err(TransportError::Disconnected); }
        let entry = self.entries.iter_mut().find(|e| e.sequence == sequence && e.hwnd == hwnd).ok_or(TransportError::Unknown)?;
        // A record still holding its bytes was never handed to the socket, so
        // the peer cannot have received it; twice-acknowledged is the same
        // protocol violation. Both end the connection at the reader.
        if entry.ack.is_some() || entry.bytes.is_some() { return Err(TransportError::Unknown); }
        entry.ack = Some(status);
        let settled = match (status, entry.opcode) {
            (0, Opcode::Frame) => Settled::Presented,
            (0, _) => Settled::Carried,
            (status, opcode) => Settled::Refused { opcode, status },
        };
        if !entry.sent { return Ok(settled); }
        let sequence = entry.sequence;
        self.settle(sequence, status);
        Ok(settled)
    }

    /// Publish one record's terminal result and release the transaction. A
    /// record nobody waits on releases its queue slot here rather than growing
    /// the queue until the connection is torn down. # C: O(records)
    fn settle(&mut self, sequence: u64, status: u32) {
        let Some(index) = self.entries.iter().position(|e| e.sequence == sequence) else { return; };
        self.entries[index].result = if status == 0 { Completion::Presented } else { Completion::Failed(status) };
        if self.entries[index].awaited { return; }
        if let Some(entry) = self.entries.remove(index) { self.bytes -= entry.charge; }
    }
    /// ACK can race final socket return; completion needs both whole transfer and ACK. # C: O(records)
    pub fn sent(&mut self, sequence: u64) -> Result<(), TransportError> {
        if self.dead { return Err(TransportError::Disconnected); }
        let entry = self.entries.iter_mut().find(|e| e.sequence == sequence).ok_or(TransportError::Unknown)?;
        if entry.bytes.is_some() { return Err(TransportError::Unknown); }
        entry.sent = true;
        let status = entry.ack;
        if let Some(status) = status { self.settle(sequence, status); }
        Ok(())
    }
    /// Pending queries do not release queue capacity; completed queries consume it. # C: O(records)
    pub fn take_completion(&mut self, sequence: u64) -> Result<Completion, TransportError> {
        if self.dead { return Err(TransportError::Disconnected); }
        let i = self.entries.iter().position(|e| e.sequence == sequence).ok_or(TransportError::Unknown)?;
        let result = self.entries[i].result;
        if result != Completion::Pending { let entry = self.entries.remove(i).ok_or(TransportError::Unknown)?; self.bytes -= entry.charge; }
        Ok(result)
    }
    /// # C: O(records)
    pub fn has_send(&self) -> bool { !self.dead && self.entries.iter().any(|e| e.bytes.is_some()) }
    /// # C: O(records)
    pub fn completion_ready(&self, sequence: u64) -> bool {
        self.dead || self.entries.iter().find(|e| e.sequence == sequence).map_or(true, |e| e.result != Completion::Pending)
    }
    /// # C: O(1)
    pub fn is_dead(&self) -> bool { self.dead }
    /// # C: O(records)
    pub fn close(&mut self) { self.dead = true; self.entries.clear(); self.bytes = 0; }
}
