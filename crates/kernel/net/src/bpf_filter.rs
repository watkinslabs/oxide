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

/// Packet and skb metadata supplied to a socket-filter runner.
pub struct FilterContext<'a> {
    pub packet: &'a [u8],
    pub protocol: u16,
    pub ifindex: Option<u32>,
    pub pay_offset: u32,
    pub hatype: u16,
}

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

    /// Reject a filter mutation before importing mutation-specific data. # C: O(1)
    pub fn ensure_mutable(&self) -> Result<(), FilterChangeError> {
        if self.state.lock().locked { Err(FilterChangeError::Locked) } else { Ok(()) }
    }

    /// Remove the filter, distinguishing absent and locked state. # C: O(1)
    pub fn detach(&self) -> Result<(), FilterChangeError> {
        let mut state = self.state.lock();
        if state.locked { return Err(FilterChangeError::Locked); }
        if state.program.is_none() { return Err(FilterChangeError::NotAttached); }
        state.program = None;
        Ok(())
    }

    /// Apply SO_LOCK_FILTER; an established lock cannot be cleared. # C: O(1)
    pub fn set_lock(&self, value: bool) -> Result<(), FilterChangeError> {
        let mut state = self.state.lock();
        if !value && state.locked { return Err(FilterChangeError::Locked); }
        if value { state.locked = true; }
        Ok(())
    }

    /// Copy listener attachment and lock state into a distinct child socket. # C: O(1)
    pub fn inherit_from(&self, parent: &Self) {
        let source = parent.state.lock();
        let mut state = self.state.lock();
        state.program = source.program.clone();
        state.locked = source.locked;
    }

    /// Build a distinct child snapshot from a listener filter. # C: O(1)
    pub fn inherited(parent: &Self) -> Self {
        let child = Self::new();
        child.inherit_from(parent);
        child
    }

    /// Run the current filter and return its Linux u32 verdict. # C: O(program)
    pub fn verdict(&self, packet: &[u8]) -> u32 {
        let program = self.state.lock().program.clone();
        match program.as_deref() {
            Some(program) => run_filter(program.kind, &program.insns, packet),
            None => u32::MAX,
        }
    }

    /// Run the current filter with Linux skb ancillary metadata. # C: O(program)
    pub fn verdict_with_context(&self, ctx: FilterContext<'_>) -> u32 {
        let program = self.state.lock().program.clone();
        match program.as_deref() {
            Some(program) => run_filter_with_context(program.kind, &program.insns, ctx),
            None => u32::MAX,
        }
    }

    /// Observe whether a program is attached. # C: O(1)
    pub fn is_attached(&self) -> bool { self.state.lock().program.is_some() }

    /// Observe irreversible SO_LOCK_FILTER state. # C: O(1)
    pub fn is_locked(&self) -> bool { self.state.lock().locked }

    /// The retained classic source of the attached program. An eBPF program
    /// carries no original classic blocks, so it cannot be dumped back out.
    /// # C: O(program bytes)
    pub fn classic_insns(&self) -> Option<Vec<u8>> {
        let state = self.state.lock();
        let program = state.program.as_deref()?;
        if program.kind != FilterKind::Classic { return None; }
        Some(program.insns.clone())
    }
}

impl Default for SocketFilter {
    fn default() -> Self { Self::new() }
}

/// Run one program that is not attached as a socket filter, returning its raw
/// u32 result. Reuseport selection reads that result as a member index rather
/// than as a keep/drop verdict. # C: O(program)
pub fn run_program(program: &FilterProgram, packet: &[u8]) -> u32 {
    run_filter(program.kind, &program.insns, packet)
}

/// `(kind, insns, packet) -> Linux socket-filter u32 verdict`.
pub type BpfFilterFn = fn(FilterKind, &[u8], &[u8]) -> u32;
pub type BpfFilterContextFn = fn(FilterKind, &[u8], FilterContext<'_>) -> u32;

static BPF_RUNNER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static BPF_CONTEXT_RUNNER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the socket-filter runner. Idempotent. # C: O(1)
pub fn install_bpf_filter_runner(f: BpfFilterFn) {
    BPF_RUNNER.store(f as *mut (), Ordering::Release);
}

/// Install the metadata-aware socket-filter runner. Idempotent. # C: O(1)
pub fn install_bpf_filter_context_runner(f: BpfFilterContextFn) {
    BPF_CONTEXT_RUNNER.store(f as *mut (), Ordering::Release);
}

fn run_filter(kind: FilterKind, insns: &[u8], packet: &[u8]) -> u32 {
    let raw = BPF_RUNNER.load(Ordering::Acquire);
    if raw.is_null() { return 0; }
    // SAFETY: install_bpf_filter_runner stores only this exact function signature.
    let f: BpfFilterFn = unsafe { core::mem::transmute(raw) };
    f(kind, insns, packet)
}

fn run_filter_with_context(kind: FilterKind, insns: &[u8], ctx: FilterContext<'_>) -> u32 {
    let raw = BPF_CONTEXT_RUNNER.load(Ordering::Acquire);
    if raw.is_null() { return run_filter(kind, insns, ctx.packet); }
    // SAFETY: install_bpf_filter_context_runner stores only this exact function signature.
    let f: BpfFilterContextFn = unsafe { core::mem::transmute(raw) };
    f(kind, insns, ctx)
}

/// Convert a positive filter verdict into retained UDP payload bytes. # C: O(1)
pub(crate) fn retained_payload_len(verdict: u32, payload_len: usize) -> Option<usize> {
    if verdict == 0 { return None; }
    let retained_packet = (verdict as usize).max(crate::udp::UDP_HDR_LEN);
    Some(payload_len.min(retained_packet - crate::udp::UDP_HDR_LEN))
}

/// Convert a filter verdict into retained TCP bytes after checksum validation. # C: O(1)
pub(crate) fn retained_tcp_len(verdict: u32, segment: &[u8]) -> Option<usize> {
    if verdict == 0 { return None; }
    let header_len = segment.get(12).map(|byte| (byte >> 4) as usize * 4)
        .unwrap_or(crate::tcp_hdr::TCP_HDR_MIN_LEN).max(crate::tcp_hdr::TCP_HDR_MIN_LEN);
    Some(segment.len().min((verdict as usize).max(header_len)))
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
    fn tcp_verdict_preserves_header_and_truncates_payload() {
        let mut segment = [0u8; 40];
        segment[12] = 5 << 4;
        assert_eq!(retained_tcp_len(0, &segment), None);
        assert_eq!(retained_tcp_len(1, &segment), Some(20));
        assert_eq!(retained_tcp_len(24, &segment), Some(24));
        assert_eq!(retained_tcp_len(u32::MAX, &segment), Some(40));
    }

    #[test]
    fn filter_lock_is_irreversible_and_detach_reports_absence() {
        let filter = SocketFilter::new();
        assert_eq!(filter.detach(), Err(FilterChangeError::NotAttached));
        filter.attach(FilterProgram { kind: FilterKind::Ebpf, insns: vec![1] }).unwrap();
        filter.set_lock(true).unwrap();
        assert!(filter.is_locked());
        assert_eq!(filter.detach(), Err(FilterChangeError::Locked));
        assert_eq!(filter.attach(FilterProgram {
            kind: FilterKind::Classic, insns: vec![2],
        }), Err(FilterChangeError::Locked));
        assert!(filter.is_attached());
        assert_eq!(filter.set_lock(false), Err(FilterChangeError::Locked));

        let child = SocketFilter::inherited(&filter);
        assert!(child.is_attached());
        assert!(child.is_locked());
    }
}
