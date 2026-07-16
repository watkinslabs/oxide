use alloc::sync::Arc;

use super::{UnixEnd, UnixMsgPair};

impl UnixMsgPair {
    /// Share the bound InetSocket's canonical error state with this endpoint. # C: O(1)
    pub fn attach_end_error(&self, end: UnixEnd, error: &Arc<crate::SocketError>) {
        *self.error_slot(end).lock() = error.clone();
    }

    /// Canonical error state allocated for an endpoint not yet bound to a socket. # C: O(1)
    pub fn end_error(&self, end: UnixEnd) -> Arc<crate::SocketError> {
        self.error_slot(end).lock().clone()
    }

    pub(super) fn error_slot(&self, end: UnixEnd)
        -> &sync::Spinlock<Arc<crate::SocketError>, sync::Socket>
    {
        match end { UnixEnd::A => &self.error_a, UnixEnd::B => &self.error_b }
    }

    /// Share one endpoint's canonical socket-filter state. # C: O(1)
    pub fn attach_end_filter(&self, end: UnixEnd,
                             filter: &Arc<crate::bpf_filter::SocketFilter>) {
        *self.filter_slot(end).lock() = filter.clone();
    }

    pub(super) fn end_filter(&self, end: UnixEnd) -> Arc<crate::bpf_filter::SocketFilter> {
        self.filter_slot(end).lock().clone()
    }

    fn filter_slot(&self, end: UnixEnd)
        -> &sync::Spinlock<Arc<crate::bpf_filter::SocketFilter>, sync::Socket>
    {
        match end { UnixEnd::A => &self.filter_a, UnixEnd::B => &self.filter_b }
    }
}
