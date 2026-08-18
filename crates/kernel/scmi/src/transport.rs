//! Synchronous SCMI request/response transport boundary.

use crate::Result;

/// A serialized SCMI protocol transport.
///
/// `call` receives payload bytes without the SCMI shared-memory header or
/// status word. On success it writes response payload bytes into `rx` and
/// returns their exact count.
pub trait Transport: Send + Sync {
    /// Submit one SCMI command and collect its response. # C: O(transport)
    fn call(&self, protocol: u8, command: u8, tx: &[u8], rx: &mut [u8]) -> Result<usize>;
}
