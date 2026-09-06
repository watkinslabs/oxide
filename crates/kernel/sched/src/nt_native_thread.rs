//! Canonical Task-owned native creation/attachment state (`31n§2`).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase { Preparing, Ready, Published, Running, Returning }

#[derive(Clone, Copy)]
pub struct Request {
    pub generation: u64, pub output: u64, pub start: u64, pub parameter: u64,
    pub stack_size: u64, pub suspended: bool, pub child: Option<u32>,
}

#[derive(Clone, Copy)]
pub struct Child {
    pub creator: u32, pub generation: u64, pub phase: Phase,
    pub stack: u64, pub size: u64, pub start: u64, pub parameter: u64,
}

pub struct State {
    pub generation: u64, pub request: Option<Request>, pub child: Option<Child>,
    /// Architecture syscall frame saved at native ENTER, never a second task context.
    pub resume: Option<[u64; 40]>, pub terminate: Option<u32>, pub result: Option<u32>,
}

impl State {
    /// Empty per-Task attachment state. # C: O(1)
    pub const fn new() -> Self {
        Self { generation: 0, request: None, child: None, resume: None, terminate: None, result: None }
    }
    /// Windows callbacks require completed native attachment and PE entry. # C: O(1)
    pub fn callbacks_ready(&self) -> bool { self.child.is_none_or(|child| child.phase == Phase::Running) }
    /// Native teardown cannot be parked by an NT suspend request. # C: O(1)
    pub fn returning(&self) -> bool { self.child.is_some_and(|child| child.phase == Phase::Returning) }
    /// Native frames and in-flight factories must finish before forced PE return. # C: O(1)
    pub fn termination_ready(&self, pe_pc: bool) -> bool {
        pe_pc && self.request.is_none() && self.resume.is_some() && self.terminate.is_some()
            && self.child.is_some_and(|child| child.phase == Phase::Running)
    }
    /// Admit each attachment transition exactly once. # C: O(1)
    pub fn advance(&mut self, from: Phase, to: Phase) -> bool {
        if !matches!((from, to), (Phase::Preparing, Phase::Ready) | (Phase::Ready, Phase::Published)
            | (Phase::Published, Phase::Running) | (Phase::Running, Phase::Returning)) { return false; }
        let Some(child) = self.child.as_mut() else { return false; };
        if child.phase != from { return false; }
        child.phase = to;
        true
    }
    /// First native terminal request wins; absent/native-finished tasks cannot restart. # C: O(1)
    pub fn request_termination(&mut self, status: u32) -> bool {
        if self.child.is_none() { return false; }
        if self.result.is_none() && self.terminate.is_none() { self.terminate = Some(status); }
        true
    }
    /// Consume the saved native continuation once, preserving a queued forced status. # C: O(1)
    pub fn finish(&mut self, status: u32) -> Option<([u64; 40], u32)> {
        if !self.child.is_some_and(|child| child.phase == Phase::Running) { return None; }
        let frame = self.resume.take()?;
        self.child.as_mut()?.phase = Phase::Returning;
        let status = self.terminate.take().unwrap_or(status);
        self.result = Some(status);
        Some((frame, status))
    }
}

#[cfg(test)]
#[path = "nt_native_thread/tests.rs"]
mod tests;
