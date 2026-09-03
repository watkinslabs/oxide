//! State owned by one native NT named-pipe object.

use alloc::{collections::VecDeque, sync::Arc};
use sync::{Spinlock, TaskList as TaskListClass};

/// The side of a named-pipe connection owned by one handle.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtPipeSide { Server, Client }

/// Result of a nonblocking pipe operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtPipeIo { Complete(usize), WouldBlock, BrokenPipe }

struct PipeTransport {
    server_to_client: VecDeque<u8>,
    client_to_server: VecDeque<u8>,
    server_closed: bool,
    client_closed: bool,
    connected: bool,
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
}

/// A directional handle view over one shared named-pipe transport.
pub struct NtPipeEndpoint { pipe: Arc<NtPipe>, side: NtPipeSide }

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
            server_closed: false, client_closed: false, connected: false,
        }) }
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
        if transport.connected || transport.server_closed || transport.client_closed { return false; }
        transport.connected = true;
        true
    }

    pub fn endpoint(self: &Arc<Self>, side: NtPipeSide) -> NtPipeEndpoint {
        NtPipeEndpoint { pipe: Arc::clone(self), side }
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
        if count == 0 { NtPipeIo::WouldBlock } else { NtPipeIo::Complete(count) }
    }

    fn read(&self, side: NtPipeSide, output: &mut [u8]) -> NtPipeIo {
        let mut transport = self.transport.lock();
        let queue = match side { NtPipeSide::Server => &mut transport.client_to_server, NtPipeSide::Client => &mut transport.server_to_client };
        let count = output.len().min(queue.len());
        for byte in &mut output[..count] { *byte = queue.pop_front().unwrap(); }
        if count != 0 { return NtPipeIo::Complete(count); }
        let peer_closed = match side { NtPipeSide::Server => transport.client_closed, NtPipeSide::Client => transport.server_closed };
        if peer_closed { NtPipeIo::BrokenPipe } else { NtPipeIo::WouldBlock }
    }

    fn close(&self, side: NtPipeSide) {
        let mut transport = self.transport.lock();
        match side { NtPipeSide::Server => transport.server_closed = true, NtPipeSide::Client => transport.client_closed = true }
    }
}

impl NtPipeEndpoint {
    pub fn write(&self, data: &[u8]) -> NtPipeIo { self.pipe.write(self.side, data) }
    pub fn read(&self, output: &mut [u8]) -> NtPipeIo { self.pipe.read(self.side, output) }
    pub fn close(&self) { self.pipe.close(self.side); }
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
        assert!(pipe.connect());
        assert_eq!(server.write(b"abcd"), NtPipeIo::Complete(3));
        assert_eq!(server.write(b"z"), NtPipeIo::WouldBlock);
    }
}
