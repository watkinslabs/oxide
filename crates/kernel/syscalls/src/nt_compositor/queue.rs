use alloc::{collections::VecDeque, vec::Vec};
use syscall::nt_compositor::{self as wire, Opcode, Record};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError { Invalid, Full, Disconnected, Unknown, NoMemory, Busy, Timeout }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion { Pending, Presented, Failed(u32) }
pub(super) struct Prepared { bytes: Vec<u8>, hwnd: u64, opcode: Opcode }
struct Entry { sequence: u64, hwnd: u64, opcode: Opcode, charge: usize, bytes: Option<Vec<u8>>, result: Completion, sent: bool, ack: Option<u32>, awaited: bool }
pub struct Queue { entries: VecDeque<Entry>, bytes: usize, next: u64, active: Option<u64>, dead: bool }

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
    pub const fn new() -> Self { Self { entries: VecDeque::new(), bytes: 0, next: 1, active: None, dead: false } }
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
    /// One outstanding stream transaction bounds socket buffering and ACK ownership. # C: O(records)
    pub fn take_send(&mut self) -> Option<Vec<u8>> {
        if self.dead || self.active.is_some() { return None; }
        let entry = self.entries.iter_mut().find(|e| e.bytes.is_some())?;
        self.active = Some(entry.sequence); entry.bytes.take()
    }
    /// # C: O(records)
    /// Answers whether the acknowledgement settled a presented frame, which
    /// is the desktop confirming pixels it was handed rather than a control
    /// request it carried out. # C: O(records)
    pub fn acknowledge(&mut self, sequence: u64, hwnd: u64, status: u32) -> Result<bool, TransportError> {
        if self.dead { return Err(TransportError::Disconnected); }
        if self.active != Some(sequence) { return Err(TransportError::Unknown); }
        let entry = self.entries.iter_mut().find(|e| e.sequence == sequence && e.hwnd == hwnd).ok_or(TransportError::Unknown)?;
        if entry.ack.is_some() { return Err(TransportError::Unknown); }
        entry.ack = Some(status);
        let frame = entry.opcode == Opcode::Frame && status == 0;
        if !entry.sent { return Ok(false); }
        let sequence = entry.sequence;
        self.settle(sequence, status);
        Ok(frame)
    }

    /// Publish one record's terminal result and release the transaction. A
    /// record nobody waits on releases its queue slot here rather than growing
    /// the queue until the connection is torn down. # C: O(records)
    fn settle(&mut self, sequence: u64, status: u32) {
        let Some(index) = self.entries.iter().position(|e| e.sequence == sequence) else { return; };
        self.entries[index].result = if status == 0 { Completion::Presented } else { Completion::Failed(status) };
        self.active = None;
        if self.entries[index].awaited { return; }
        if let Some(entry) = self.entries.remove(index) { self.bytes -= entry.charge; }
    }
    /// ACK can race final socket return; completion needs both whole transfer and ACK. # C: O(records)
    pub fn sent(&mut self) -> Result<(), TransportError> {
        if self.dead { return Err(TransportError::Disconnected); }
        let sequence = self.active.ok_or(TransportError::Unknown)?;
        let entry = self.entries.iter_mut().find(|e| e.sequence == sequence).ok_or(TransportError::Unknown)?;
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
    /// The record this queue currently has in flight on the stream. # C: O(1)
    pub fn active(&self) -> Option<u64> { self.active }
    /// # C: O(records)
    pub fn has_send(&self) -> bool { !self.dead && self.active.is_none() && self.entries.iter().any(|e| e.bytes.is_some()) }
    /// # C: O(records)
    pub fn completion_ready(&self, sequence: u64) -> bool {
        self.dead || self.entries.iter().find(|e| e.sequence == sequence).map_or(true, |e| e.result != Completion::Pending)
    }
    /// # C: O(1)
    pub fn is_dead(&self) -> bool { self.dead }
    /// # C: O(records)
    pub fn close(&mut self) { self.dead = true; self.entries.clear(); self.bytes = 0; self.active = None; }
}
