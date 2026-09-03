//! State owned by one native NT named-pipe object.

use alloc::{collections::VecDeque, sync::Arc};
use crate::live::WaitList;
use crate::WaitOutcome;
use sync::{Spinlock, TaskList as TaskListClass};

/// The side of a named-pipe connection owned by one handle.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtPipeSide { Server, Client }

/// Result of a nonblocking pipe operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtPipeIo { Complete(usize), WouldBlock, BrokenPipe }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtPipeListen { Pending, Connected }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtPipePeek { pub state: u32, pub available: usize, pub messages: usize, pub message_length: usize, pub data: alloc::vec::Vec<u8> }

struct PipeTransport {
    server_to_client: VecDeque<u8>,
    client_to_server: VecDeque<u8>,
    server_closed: bool,
    client_closed: bool,
    connected: bool,
    listening: bool,
}

/// Immutable configuration supplied when a named-pipe instance is created.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtPipeConfig {
    pub pipe_type: u32,
    pub read_mode: u32,
    pub completion_mode: u32,
    pub max_instances: u32,
    pub inbound_quota: u32,
    pub outbound_quota: u32,
    pub timeout_100ns: i64,
    pub sharing: u32,
}

/// Connection-independent state shared by all handles for one named pipe.
/// Endpoint queues and connection transitions will be added here as the
/// FSCTL and asynchronous I/O lanes land; configuration is already canonical.
pub struct NtPipe {
    config: NtPipeConfig,
    instances: Spinlock<u32, TaskListClass>,
    transport: Spinlock<PipeTransport, TaskListClass>,
    read_waiters: WaitList,
    write_waiters: WaitList,
}

/// A directional handle view over one shared named-pipe transport.
pub struct NtPipeEndpoint {
    pipe: Arc<NtPipe>, side: NtPipeSide, reserved: bool,
    modes: Spinlock<(u32, u32), TaskListClass>,
}

impl NtPipe {
    /// Validate the immutable portion of `NtCreateNamedPipeFile` before an
    /// object can enter the namespace. These checks mirror Wine's server
    /// admission boundary; transport and endpoint state are separate.
    pub fn validate_create(config: NtPipeConfig, access: u32) -> bool {
        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;
        const PIPE_TYPE_MESSAGE: u32 = 0x0000_0001;
        const PIPE_READMODE_MESSAGE: u32 = 0x0000_0001;
        const PIPE_WAIT: u32 = 0;
        const PIPE_NOWAIT: u32 = 1;
        if access == 0 || config.sharing == 0 || config.sharing & !(FILE_SHARE_READ | FILE_SHARE_WRITE) != 0 {
            return false;
        }
        if config.max_instances == 0 || config.inbound_quota == 0 || config.outbound_quota == 0 {
            return false;
        }
        if config.pipe_type & !PIPE_TYPE_MESSAGE != 0
            || config.read_mode & !PIPE_READMODE_MESSAGE != 0
            || config.completion_mode & !(PIPE_WAIT | PIPE_NOWAIT) != 0 {
            return false;
        }
        if config.pipe_type == PIPE_TYPE_MESSAGE && config.read_mode == PIPE_READMODE_MESSAGE {
            return true;
        }
        config.pipe_type == 0 && config.read_mode == 0
    }

    pub fn new(config: NtPipeConfig) -> Self {
        Self { config, instances: Spinlock::new(0), transport: Spinlock::new(PipeTransport {
            server_to_client: VecDeque::new(), client_to_server: VecDeque::new(),
            server_closed: false, client_closed: false, connected: false, listening: false,
        }), read_waiters: WaitList::new(), write_waiters: WaitList::new() }
    }

    pub fn config(&self) -> NtPipeConfig { self.config }
    pub fn instances(&self) -> u32 { *self.instances.lock() }

    /// Reserve one server instance without exceeding the NT limit.
    pub fn reserve_instance(&self) -> bool {
        let mut instances = self.instances.lock();
        if *instances >= self.config.max_instances { return false; }
        *instances += 1;
        true
    }

    pub fn release_instance(&self) {
        let mut instances = self.instances.lock();
        *instances = instances.saturating_sub(1);
    }

    /// Establish one client/server connection for this pipe instance.
    pub fn connect(&self) -> bool {
        let mut transport = self.transport.lock();
        if transport.connected || !transport.listening || transport.server_closed || transport.client_closed { return false; }
        transport.connected = true;
        transport.listening = false;
        drop(transport);
        self.read_waiters.wake_all();
        self.write_waiters.wake_all();
        true
    }

    pub fn listen(&self) -> NtPipeListen {
        let mut transport = self.transport.lock();
        if transport.connected { return NtPipeListen::Connected; }
        if transport.server_closed { return NtPipeListen::Pending; }
        transport.listening = true;
        NtPipeListen::Pending
    }

    pub fn peek(&self, side: NtPipeSide, capacity: usize) -> NtPipePeek {
        let transport = self.transport.lock();
        let queue = match side { NtPipeSide::Server => &transport.client_to_server, NtPipeSide::Client => &transport.server_to_client };
        let state = if transport.connected { 3 } else if transport.listening { 2 } else { 1 };
        let message_mode = self.config.pipe_type != 0;
        let message_length = if message_mode && !queue.is_empty() { queue.len() } else { 0 };
        let count = queue.len().min(capacity).min(if message_mode { message_length } else { usize::MAX });
        NtPipePeek { state, available: queue.len(), messages: usize::from(message_mode && !queue.is_empty()), message_length, data: queue.iter().take(count).copied().collect() }
    }

    pub fn information(&self, side: NtPipeSide) -> ([u32; 2], [u32; 10]) {
        let transport = self.transport.lock();
        let queue = match side { NtPipeSide::Server => &transport.client_to_server, NtPipeSide::Client => &transport.server_to_client };
        let state = if transport.connected { 3 } else if transport.listening { 2 } else { 1 };
        let read_mode = u32::from(self.config.read_mode != 0);
        let completion_mode = u32::from(self.config.completion_mode != 0);
        let configuration = match self.config.sharing { 1 => 1, 2 => 2, _ => 3 };
        let end = u32::from(side == NtPipeSide::Server);
        let quota = match side { NtPipeSide::Server => self.config.outbound_quota, NtPipeSide::Client => self.config.inbound_quota };
        ([read_mode, completion_mode], [self.config.pipe_type, configuration,
            self.config.max_instances, self.instances(), self.config.inbound_quota,
            queue.len() as u32, self.config.outbound_quota,
            quota.saturating_sub(queue.len() as u32), state, end])
    }

    pub fn endpoint(self: &Arc<Self>, side: NtPipeSide) -> NtPipeEndpoint {
        NtPipeEndpoint { pipe: Arc::clone(self), side, reserved: false,
            modes: Spinlock::new((u32::from(self.config.read_mode != 0), u32::from(self.config.completion_mode != 0))) }
    }

    pub fn endpoint_with_instance(self: &Arc<Self>, side: NtPipeSide) -> NtPipeEndpoint {
        NtPipeEndpoint { pipe: Arc::clone(self), side, reserved: true,
            modes: Spinlock::new((u32::from(self.config.read_mode != 0), u32::from(self.config.completion_mode != 0))) }
    }

    fn write(&self, side: NtPipeSide, data: &[u8]) -> NtPipeIo {
        let mut transport = self.transport.lock();
        let peer_closed = match side { NtPipeSide::Server => transport.client_closed, NtPipeSide::Client => transport.server_closed };
        if peer_closed { return NtPipeIo::BrokenPipe; }
        if !transport.connected { return NtPipeIo::WouldBlock; }
        let queue = match side { NtPipeSide::Server => &mut transport.server_to_client, NtPipeSide::Client => &mut transport.client_to_server };
        let quota = match side { NtPipeSide::Server => self.config.outbound_quota, NtPipeSide::Client => self.config.inbound_quota } as usize;
        let count = data.len().min(quota.saturating_sub(queue.len()));
        queue.extend(data[..count].iter().copied());
        let result = if count == 0 { NtPipeIo::WouldBlock } else { NtPipeIo::Complete(count) };
        drop(transport);
        if count != 0 { self.read_waiters.wake_all(); }
        result
    }

    fn read(&self, side: NtPipeSide, output: &mut [u8]) -> NtPipeIo {
        let mut transport = self.transport.lock();
        let queue = match side { NtPipeSide::Server => &mut transport.client_to_server, NtPipeSide::Client => &mut transport.server_to_client };
        let count = output.len().min(queue.len());
        for byte in &mut output[..count] { *byte = queue.pop_front().unwrap(); }
        if count != 0 {
            drop(transport);
            self.write_waiters.wake_all();
            return NtPipeIo::Complete(count);
        }
        let peer_closed = match side { NtPipeSide::Server => transport.client_closed, NtPipeSide::Client => transport.server_closed };
        let result = if peer_closed { NtPipeIo::BrokenPipe } else { NtPipeIo::WouldBlock };
        drop(transport);
        result
    }

    fn close(&self, side: NtPipeSide) {
        let mut transport = self.transport.lock();
        match side { NtPipeSide::Server => transport.server_closed = true, NtPipeSide::Client => transport.client_closed = true }
        drop(transport);
        self.read_waiters.wake_all();
        self.write_waiters.wake_all();
    }

    fn disconnect(&self) {
        let mut transport = self.transport.lock();
        transport.server_to_client.clear();
        transport.client_to_server.clear();
        transport.server_closed = false;
        transport.client_closed = false;
        transport.connected = false;
        transport.listening = false;
        drop(transport);
        self.read_waiters.wake_all();
        self.write_waiters.wake_all();
    }

    fn read_ready(&self, side: NtPipeSide) -> bool {
        let transport = self.transport.lock();
        let queue = match side { NtPipeSide::Server => &transport.client_to_server, NtPipeSide::Client => &transport.server_to_client };
        let peer_closed = match side { NtPipeSide::Server => transport.client_closed, NtPipeSide::Client => transport.server_closed };
        !queue.is_empty() || peer_closed
    }

    fn write_ready(&self, side: NtPipeSide) -> bool {
        let transport = self.transport.lock();
        let peer_closed = match side { NtPipeSide::Server => transport.client_closed, NtPipeSide::Client => transport.server_closed };
        let queue = match side { NtPipeSide::Server => &transport.server_to_client, NtPipeSide::Client => &transport.client_to_server };
        let quota = match side { NtPipeSide::Server => self.config.outbound_quota, NtPipeSide::Client => self.config.inbound_quota } as usize;
        peer_closed || (transport.connected && queue.len() < quota)
    }

    /// Wait until the endpoint can make progress, preserving the scheduler's
    /// prepare/recheck/park ordering used by every blocking kernel path.
    /// # Sleeps: yes
    pub unsafe fn wait_for_io(&self, side: NtPipeSide, write: bool, deadline_ns: u64,
                              now: impl Fn() -> u64) -> WaitOutcome {
        let waiters = if write { &self.write_waiters } else { &self.read_waiters };
        // SAFETY: the native syscall caller is process context and owns no
        // transport lock while the scheduler parks the current task.
        unsafe { crate::live::wait_event_interruptible_until(waiters, deadline_ns, now, || {
            if write { self.write_ready(side) } else { self.read_ready(side) }
        }) }
    }
}

impl NtPipeEndpoint {
    pub fn pipe(&self) -> Arc<NtPipe> { Arc::clone(&self.pipe) }
    pub fn write(&self, data: &[u8]) -> NtPipeIo { self.pipe.write(self.side, data) }
    pub fn read(&self, output: &mut [u8]) -> NtPipeIo { self.pipe.read(self.side, output) }
    pub fn completion_mode(&self) -> u32 { self.modes.lock().1 }
    /// # Sleeps: yes
    pub unsafe fn wait_for_io(&self, write: bool, deadline_ns: u64,
                              now: impl Fn() -> u64) -> WaitOutcome {
        // SAFETY: forwards the endpoint's process-context wait contract.
        unsafe { self.pipe.wait_for_io(self.side, write, deadline_ns, now) }
    }
    pub fn close(&self) { self.pipe.close(self.side); }
    pub fn disconnect(&self) -> bool {
        if self.side != NtPipeSide::Server { return false; }
        self.pipe.disconnect();
        true
    }
    pub fn listen(&self) -> NtPipeListen {
        if self.side != NtPipeSide::Server { return NtPipeListen::Pending; }
        self.pipe.listen()
    }
    pub fn peek(&self, capacity: usize) -> NtPipePeek { self.pipe.peek(self.side, capacity) }
    pub fn information(&self) -> ([u32; 2], [u32; 10]) {
        let modes = *self.modes.lock();
        let (_, local) = self.pipe.information(self.side);
        ([modes.0, modes.1], local)
    }
    pub fn set_modes(&self, read_mode: u32, completion_mode: u32) -> bool {
        if read_mode > 1 || completion_mode > 1 { return false; }
        *self.modes.lock() = (read_mode, completion_mode);
        true
    }
}

impl Drop for NtPipeEndpoint {
    fn drop(&mut self) {
        if self.reserved && self.side == NtPipeSide::Server { self.pipe.release_instance(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(max_instances: u32) -> NtPipeConfig {
        NtPipeConfig { pipe_type: 0, read_mode: 0, completion_mode: 0,
            max_instances, inbound_quota: 4096, outbound_quota: 4096,
            timeout_100ns: -1, sharing: 3 }
    }

    #[test]
    fn instance_admission_is_object_owned() {
        let pipe = NtPipe::new(config(2));
        assert!(pipe.reserve_instance());
        assert!(pipe.reserve_instance());
        assert!(!pipe.reserve_instance());
        pipe.release_instance();
        assert!(pipe.reserve_instance());
        assert_eq!(pipe.instances(), 2);
    }

    #[test]
    fn configuration_is_shared_without_mutation() {
        let expected = config(7);
        assert_eq!(NtPipe::new(expected).config(), expected);
    }

    #[test]
    fn create_admission_rejects_invalid_sharing_and_zero_resources() {
        let mut value = config(1);
        assert!(NtPipe::validate_create(value, 1));
        value.sharing = 4;
        assert!(!NtPipe::validate_create(value, 1));
        value = config(1);
        value.inbound_quota = 0;
        assert!(!NtPipe::validate_create(value, 1));
    }

    #[test]
    fn create_admission_requires_access_and_known_modes() {
        let value = config(1);
        assert!(!NtPipe::validate_create(value, 0));
        let mut bad = value;
        bad.pipe_type = 2;
        assert!(!NtPipe::validate_create(bad, 1));
    }

    #[test]
    fn endpoints_exchange_directional_data_and_report_peer_close() {
        let pipe = Arc::new(NtPipe::new(config(1)));
        let server = pipe.endpoint(NtPipeSide::Server);
        let client = pipe.endpoint(NtPipeSide::Client);
        assert_eq!(server.write(b"x"), NtPipeIo::WouldBlock);
        assert_eq!(pipe.listen(), NtPipeListen::Pending);
        assert!(pipe.connect());
        assert_eq!(server.write(b"hello"), NtPipeIo::Complete(5));
        let mut output = [0u8; 8];
        assert_eq!(client.read(&mut output), NtPipeIo::Complete(5));
        assert_eq!(&output[..5], b"hello");
        client.close();
        assert_eq!(server.write(b"x"), NtPipeIo::BrokenPipe);
    }

    #[test]
    fn full_queue_backpressure_is_nonblocking_and_bounded() {
        let config = NtPipeConfig { outbound_quota: 3, ..config(1) };
        let pipe = Arc::new(NtPipe::new(config));
        let server = pipe.endpoint(NtPipeSide::Server);
        assert_eq!(pipe.listen(), NtPipeListen::Pending);
        assert!(pipe.connect());
        assert_eq!(server.write(b"abcd"), NtPipeIo::Complete(3));
        assert_eq!(server.write(b"z"), NtPipeIo::WouldBlock);
    }

    #[test]
    fn server_disconnect_resets_connection_and_discards_queued_data() {
        let pipe = Arc::new(NtPipe::new(config(1)));
        let server = pipe.endpoint(NtPipeSide::Server);
        let client = pipe.endpoint(NtPipeSide::Client);
        assert_eq!(pipe.listen(), NtPipeListen::Pending);
        assert!(pipe.connect());
        assert_eq!(server.write(b"stale"), NtPipeIo::Complete(5));
        assert!(server.disconnect());
        let mut output = [0u8; 8];
        assert_eq!(client.read(&mut output), NtPipeIo::WouldBlock);
        assert_eq!(pipe.listen(), NtPipeListen::Pending);
        assert!(pipe.connect());
        assert_eq!(server.write(b"fresh"), NtPipeIo::Complete(5));
        assert_eq!(client.read(&mut output), NtPipeIo::Complete(5));
    }

    #[test]
    fn peek_snapshots_without_consuming_directional_data() {
        let pipe = Arc::new(NtPipe::new(config(1)));
        let server = pipe.endpoint(NtPipeSide::Server);
        let client = pipe.endpoint(NtPipeSide::Client);
        assert_eq!(pipe.listen(), NtPipeListen::Pending);
        assert!(pipe.connect());
        assert_eq!(server.write(b"peek-me"), NtPipeIo::Complete(7));
        let snapshot = client.peek(4);
        assert_eq!(snapshot.state, 3);
        assert_eq!(snapshot.available, 7);
        assert_eq!(snapshot.data, b"peek".to_vec());
        let mut output = [0u8; 8];
        assert_eq!(client.read(&mut output), NtPipeIo::Complete(7));
    }

    #[test]
    fn information_reports_endpoint_state_and_directional_quota() {
        let pipe = Arc::new(NtPipe::new(config(2)));
        let server = pipe.endpoint(NtPipeSide::Server);
        let client = pipe.endpoint(NtPipeSide::Client);
        assert_eq!(server.information().1[8], 1);
        assert_eq!(server.information().1[9], 1);
        assert_eq!(pipe.listen(), NtPipeListen::Pending);
        assert_eq!(server.information().1[8], 2);
        assert!(pipe.connect());
        assert_eq!(client.information().1[8], 3);
        assert_eq!(client.information().1[9], 0);
    }

    #[test]
    fn endpoint_modes_are_mutable_per_handle_and_reject_unknown_values() {
        let pipe = Arc::new(NtPipe::new(config(1)));
        let server = pipe.endpoint(NtPipeSide::Server);
        let client = pipe.endpoint(NtPipeSide::Client);
        assert!(server.set_modes(1, 1));
        assert_eq!(server.information().0, [1, 1]);
        assert_eq!(client.information().0, [0, 0]);
        assert!(!server.set_modes(2, 0));
        assert!(!server.set_modes(0, 2));
    }

    #[test]
    fn final_server_handle_releases_reserved_instance() {
        let table = crate::nt_object::NtHandleTable::new();
        let pipe = Arc::new(NtPipe::new(config(1)));
        assert!(pipe.reserve_instance());
        let object = table.new_named_pipe_endpoint(Arc::clone(&pipe), NtPipeSide::Server);
        let handle = table.insert(Arc::clone(&object), 1).unwrap();
        let duplicate = table.duplicate(handle, 1).unwrap();
        drop(object);

        assert_eq!(pipe.instances(), 1);
        assert!(table.close(handle));
        assert_eq!(pipe.instances(), 1);
        assert!(table.close(duplicate));
        assert_eq!(pipe.instances(), 0);
    }
}
