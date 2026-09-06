//! Target-independent admission for the NT registry endpoint carried by one
//! execution handoff.  The launcher connects the registry under its own
//! credentials and namespaces and hands the connected descriptor across; the
//! kernel never reopens a pathname on the process's behalf, so this module
//! owns only the decisions about the supplied descriptor value and about a
//! transaction attempted without an endpoint.

/// `NtExecRequest` supplies no registry endpoint.
pub const NO_ENDPOINT: i32 = syscall::nt_exec::NO_REGISTRY_ENDPOINT;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;

/// What one handoff's registry descriptor field selects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endpoint {
    /// The launch declines a registry; NT registry calls stay unserviced.
    Absent,
    /// Resolve this descriptor in the caller's table and retain the file.
    Descriptor(i32),
    /// The field cannot name a descriptor; the whole handoff is rejected.
    Rejected(u64),
}

/// Classify the raw 32-bit descriptor field of one execution request.
/// Only `NO_ENDPOINT` means absent: every other negative value is a caller
/// error rather than a silent decline, because a launcher that intended an
/// endpoint and computed a bad descriptor must not start without a registry.
pub const fn classify(raw: i32) -> Endpoint {
    if raw == NO_ENDPOINT { return Endpoint::Absent; }
    if raw < 0 { return Endpoint::Rejected(STATUS_INVALID_PARAMETER); }
    Endpoint::Descriptor(raw)
}

/// Status for a registry transaction attempted by a process whose launch
/// admitted no endpoint.  This is a refusal, never a fabricated success and
/// never an empty result that a caller could read as "key absent".
pub const fn no_endpoint_status() -> u64 { STATUS_ACCESS_DENIED }

/// Status for a handoff whose descriptor names no connected stream socket.
pub const fn not_a_socket_status() -> u64 { STATUS_INVALID_PARAMETER }

#[cfg(test)]
#[path = "tests/nt_registry_endpoint.rs"]
mod tests;
