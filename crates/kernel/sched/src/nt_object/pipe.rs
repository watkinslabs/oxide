//! State owned by one native NT named-pipe object.

use sync::{Spinlock, TaskList as TaskListClass};

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
        Self { config, instances: Spinlock::new(0) }
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
}
