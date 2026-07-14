// Linux socket-filter state and runner bridge. Security owns both interpreters;
// net owns attachment lifetime and UDP truncation semantics.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
use sync::{Spinlock, Socket as SockLockClass};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FilterKind { Classic, Ebpf }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilterProgram {
    pub kind: FilterKind,
    pub insns: Vec<u8>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FilterChangeError { Locked, NotAttached }

struct FilterState {
    program: Option<Arc<FilterProgram>>,
    locked: bool,
}

/// Canonical per-socket filter attachment and irreversible lock state.
pub struct SocketFilter {
    state: Spinlock<FilterState, SockLockClass>,
}

impl SocketFilter {
    /// Build an unlocked socket with no filter. # C: O(1)
    pub fn new() -> Self {
        Self { state: Spinlock::new(FilterState { program: None, locked: false }) }
    }

    /// Replace the attached filter unless SO_LOCK_FILTER is set. # C: O(program bytes)
    pub fn attach(&self, program: FilterProgram) -> Result<(), FilterChangeError> {
        let mut state = self.state.lock();
        if state.locked { return Err(FilterChangeError::Locked); }
        state.program = Some(Arc::new(program));
        Ok(())
    }

    /// Remove the filter, distinguishing absent and locked state. # C: O(1)
    pub fn detach(&self) -> Result<(), FilterChangeError> {
        let mut state = self.state.lock();
        if state.locked { return Err(FilterChangeError::Locked); }
        if state.program.is_none() { return Err(FilterChangeError::NotAttached); }
        state.program = None;
        Ok(())
    }

    /// Irreversibly prevent filter replacement and removal. # C: O(1)
    pub fn lock(&self) { self.state.lock().locked = true; }

    /// Run the current filter and return its Linux u32 verdict. # C: O(program)
    pub fn verdict(&self, packet: &[u8]) -> u32 {
        let program = self.state.lock().program.clone();
        match program.as_deref() {
            Some(program) => run_filter(program.kind, &program.insns, packet),
            None => u32::MAX,
        }
    }

    /// Observe whether a program is attached. # C: O(1)
    pub fn is_attached(&self) -> bool { self.state.lock().program.is_some() }

    /// Observe irreversible SO_LOCK_FILTER state. # C: O(1)
    pub fn is_locked(&self) -> bool { self.state.lock().locked }
}

impl Default for SocketFilter {
    fn default() -> Self { Self::new() }
}

/// `(kind, insns, packet) -> Linux socket-filter u32 verdict`.
pub type BpfFilterFn = fn(FilterKind, &[u8], &[u8]) -> u32;

static BPF_RUNNER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the socket-filter runner. Idempotent. # C: O(1)
pub fn install_bpf_filter_runner(f: BpfFilterFn) {
    BPF_RUNNER.store(f as *mut (), Ordering::Release);
}

fn run_filter(kind: FilterKind, insns: &[u8], packet: &[u8]) -> u32 {
    let raw = BPF_RUNNER.load(Ordering::Acquire);
    if raw.is_null() { return 0; }
    // SAFETY: install_bpf_filter_runner stores only this exact function signature.
    let f: BpfFilterFn = unsafe { core::mem::transmute(raw) };
    f(kind, insns, packet)
}

/// Convert a positive filter verdict into retained UDP payload bytes. # C: O(1)
pub(crate) fn retained_payload_len(verdict: u32, payload_len: usize) -> Option<usize> {
    if verdict == 0 { return None; }
    let retained_packet = (verdict as usize).max(crate::udp::UDP_HDR_LEN);
    Some(payload_len.min(retained_packet - crate::udp::UDP_HDR_LEN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn verdict_zero_drops_and_positive_verdict_truncates_after_udp_header() {
        assert_eq!(retained_payload_len(0, 32), None);
        assert_eq!(retained_payload_len(1, 32), Some(0));
        assert_eq!(retained_payload_len(8, 32), Some(0));
        assert_eq!(retained_payload_len(11, 32), Some(3));
        assert_eq!(retained_payload_len(u32::MAX, 32), Some(32));
    }

    #[test]
    fn filter_lock_is_irreversible_and_detach_reports_absence() {
        let filter = SocketFilter::new();
        assert_eq!(filter.detach(), Err(FilterChangeError::NotAttached));
        filter.attach(FilterProgram { kind: FilterKind::Ebpf, insns: vec![1] }).unwrap();
        filter.lock();
        assert!(filter.is_locked());
        assert_eq!(filter.detach(), Err(FilterChangeError::Locked));
        assert_eq!(filter.attach(FilterProgram {
            kind: FilterKind::Classic, insns: vec![2],
        }), Err(FilterChangeError::Locked));
        assert!(filter.is_attached());
    }
}
