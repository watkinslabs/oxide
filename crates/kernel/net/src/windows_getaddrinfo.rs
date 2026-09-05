//! Bounded Windows `getaddrinfo` result contract over the native resolver.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::{IpAddr, Ipv6Addr, Port};

/// Maximum records copied across the native/Windows resolver boundary.
pub const MAX_ADDRINFO_RESULTS: usize = 32;
/// Maximum canonical-name bytes copied, excluding the terminating NUL.
pub const MAX_CANONICAL_NAME: usize = 255;

/// Winsock `getaddrinfo` result error codes.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WinsockResolverError {
    Again = 10001,
    BadFlags = 10022,
    Fail = 10014,
    Family = 10047,
    Memory = 10055,
    NoData = 11004,
    Service = 10108,
    SockType = 10044,
    Cancelled = 995,
}

const REQUEST_IDLE: u32 = 0;
const REQUEST_PENDING: u32 = 1;
const REQUEST_COMPLETE: u32 = 2;
const REQUEST_CANCELLED: u32 = 3;
const REQUEST_COMPLETING: u32 = 4;

/// Result observed by a caller of an asynchronous resolver request.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResolverPoll {
    Pending,
    Complete(Result<(), WinsockResolverError>),
}

/// Canonical ownership of one `GetAddrInfoEx` operation's terminal state.
///
/// Address records remain owned by the resolver operation that produced them;
/// this object only publishes whether that operation completed or was
/// cancelled. Exactly one of `complete` and `cancel` can win while pending.
pub struct ResolverRequest {
    state: AtomicU32,
    error: AtomicU32,
}

impl ResolverRequest {
    /// Create an idle request that has not been submitted. # C: O(1)
    pub const fn new() -> Self {
        Self { state: AtomicU32::new(REQUEST_IDLE), error: AtomicU32::new(0) }
    }

    /// Admit one operation; a live or terminal operation cannot be overwritten. # C: O(1)
    pub fn submit(&self) -> bool {
        self.error.store(0, Ordering::Relaxed);
        self.state.compare_exchange(REQUEST_IDLE, REQUEST_PENDING,
            Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Publish the native resolver result exactly once. # C: O(1)
    pub fn complete(&self, result: Result<(), WinsockResolverError>) -> bool {
        let code = match result { Ok(()) => 0, Err(error) => error as u32 };
        if self.state.compare_exchange(REQUEST_PENDING, REQUEST_COMPLETING,
            Ordering::AcqRel, Ordering::Acquire).is_err() { return false; }
        self.error.store(code, Ordering::Relaxed);
        self.state.store(REQUEST_COMPLETE, Ordering::Release);
        true
    }

    /// WinSock cancellation is terminal and races completion by ownership of the state transition. # C: O(1)
    pub fn cancel(&self) -> bool {
        self.state.compare_exchange(REQUEST_PENDING, REQUEST_CANCELLED,
            Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Observe the terminal result after its release publication. # C: O(1)
    pub fn poll(&self) -> ResolverPoll {
        match self.state.load(Ordering::Acquire) {
            REQUEST_PENDING | REQUEST_COMPLETING | REQUEST_IDLE => ResolverPoll::Pending,
            REQUEST_CANCELLED => ResolverPoll::Complete(Err(WinsockResolverError::Cancelled)),
            REQUEST_COMPLETE => {
                let code = self.error.load(Ordering::Relaxed);
                if code == 0 { return ResolverPoll::Complete(Ok(())); }
                let error = match code {
                    x if x == WinsockResolverError::Again as u32 => WinsockResolverError::Again,
                    x if x == WinsockResolverError::BadFlags as u32 => WinsockResolverError::BadFlags,
                    x if x == WinsockResolverError::Fail as u32 => WinsockResolverError::Fail,
                    x if x == WinsockResolverError::Family as u32 => WinsockResolverError::Family,
                    x if x == WinsockResolverError::Memory as u32 => WinsockResolverError::Memory,
                    x if x == WinsockResolverError::NoData as u32 => WinsockResolverError::NoData,
                    x if x == WinsockResolverError::Service as u32 => WinsockResolverError::Service,
                    x if x == WinsockResolverError::SockType as u32 => WinsockResolverError::SockType,
                    x if x == WinsockResolverError::Cancelled as u32 => WinsockResolverError::Cancelled,
                    _ => WinsockResolverError::Fail,
                };
                ResolverPoll::Complete(Err(error))
            }
            _ => ResolverPoll::Complete(Err(WinsockResolverError::Fail)),
        }
    }

    /// Release a terminal request for explicit reuse by its owner. # C: O(1)
    pub fn reset(&self) -> bool {
        let state = self.state.load(Ordering::Acquire);
        if state != REQUEST_COMPLETE && state != REQUEST_CANCELLED { return false; }
        self.state.compare_exchange(state, REQUEST_IDLE,
            Ordering::AcqRel, Ordering::Acquire).is_ok()
    }
}

/// Resolver failure before an address list exists.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NativeResolverError {
    Again,
    BadFlags,
    Fail,
    Family,
    Memory,
    NoData,
    Noname,
    Service,
    SockType,
}

impl NativeResolverError {
    /// Map the native resolver result to the Winsock result namespace. # C: O(1)
    pub const fn into_winsock(self) -> WinsockResolverError {
        match self {
            Self::Again => WinsockResolverError::Again,
            Self::BadFlags => WinsockResolverError::BadFlags,
            Self::Fail => WinsockResolverError::Fail,
            Self::Family => WinsockResolverError::Family,
            Self::Memory => WinsockResolverError::Memory,
            Self::NoData | Self::Noname => WinsockResolverError::NoData,
            Self::Service => WinsockResolverError::Service,
            Self::SockType => WinsockResolverError::SockType,
        }
    }
}

/// One native resolver record. `canon_name` is a C-string payload without NUL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAddrInfo {
    pub flags: u32,
    pub socktype: u32,
    pub protocol: u32,
    pub address: IpAddr,
    pub port: Port,
    pub canon_name: Option<Vec<u8>>,
}

/// Native resolver return, kept separate from its Windows representation.
pub enum NativeResolverOutcome {
    Error(NativeResolverError),
    Records(Vec<NativeAddrInfo>),
}

/// Winsock sockaddr payload and its ABI length.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowsSockaddr {
    pub family: u16,
    pub len: u32,
    pub bytes: [u8; 28],
}

/// One bounded, ownership-safe Windows `addrinfo` result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsAddrInfo {
    pub flags: u32,
    pub family: u32,
    pub socktype: u32,
    pub protocol: u32,
    pub address: WindowsSockaddr,
    pub canon_name: Option<Vec<u8>>,
}

/// Input rejected before a native record can become a Windows result.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    TooManyResults,
    CanonicalNameTooLong,
    CanonicalNameContainsNul,
    UnsupportedFamily,
}

/// Translate a native resolver outcome without changing native result order. # C: O(N)
pub fn translate(outcome: NativeResolverOutcome)
    -> Result<Result<Vec<WindowsAddrInfo>, WinsockResolverError>, ContractError>
{
    let NativeResolverOutcome::Records(records) = outcome else {
        if let NativeResolverOutcome::Error(error) = outcome {
            return Ok(Err(error.into_winsock()));
        }
        unreachable!();
    };
    if records.len() > MAX_ADDRINFO_RESULTS { return Err(ContractError::TooManyResults); }
    let mut output = Vec::with_capacity(records.len());
    for record in records {
        let address = sockaddr(record.address, record.port)?;
        if let Some(name) = &record.canon_name {
            if name.len() > MAX_CANONICAL_NAME { return Err(ContractError::CanonicalNameTooLong); }
            if name.contains(&0) { return Err(ContractError::CanonicalNameContainsNul); }
        }
        let translated = WindowsAddrInfo {
            flags: record.flags, family: address.family as u32,
            socktype: record.socktype, protocol: record.protocol,
            address, canon_name: record.canon_name,
        };
        if !output.contains(&translated) { output.push(translated); }
    }
    Ok(Ok(output))
}

fn sockaddr(address: IpAddr, port: Port) -> Result<WindowsSockaddr, ContractError> {
    let mut bytes = [0u8; 28];
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    match address {
        IpAddr::V4(value) => {
            let octets = value.octets();
            bytes[0..2].copy_from_slice(&2u16.to_ne_bytes());
            bytes[4..8].copy_from_slice(&octets);
            Ok(WindowsSockaddr { family: 2, len: 16, bytes })
        }
        IpAddr::V6(Ipv6Addr(octets)) => {
            bytes[0..2].copy_from_slice(&23u16.to_ne_bytes());
            bytes[8..24].copy_from_slice(&octets);
            Ok(WindowsSockaddr { family: 23, len: 28, bytes })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::Ipv4Addr;

    fn v4(last: u8, canon_name: Option<&[u8]>) -> NativeAddrInfo {
        NativeAddrInfo { flags: 0, socktype: 1, protocol: 6,
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), port: 443,
            canon_name: canon_name.map(Vec::from) }
    }

    #[test]
    fn errors_map_to_winsock_and_noname_uses_nodata() {
        assert_eq!(translate(NativeResolverOutcome::Error(NativeResolverError::Again)).unwrap(), Err(WinsockResolverError::Again));
        assert_eq!(translate(NativeResolverOutcome::Error(NativeResolverError::Noname)).unwrap(), Err(WinsockResolverError::NoData));
    }

    #[test]
    fn maps_both_families_and_preserves_native_order() {
        let v6 = NativeAddrInfo { flags: 0, socktype: 2, protocol: 17,
            address: IpAddr::V6(Ipv6Addr::LOOPBACK), port: 53, canon_name: None };
        let result = translate(NativeResolverOutcome::Records(vec![v6.clone(), v4(7, Some(b"dns.example"))])).unwrap().unwrap();
        assert_eq!(result[0].family, 23);
        assert_eq!(result[0].address.len, 28);
        assert_eq!(&result[0].address.bytes[2..4], &53u16.to_be_bytes());
        assert_eq!(result[1].family, 2);
        assert_eq!(result[1].canon_name, Some(Vec::from(&b"dns.example"[..])));
        assert_eq!(&result[1].address.bytes[4..8], &[192, 0, 2, 7]);
    }

    #[test]
    fn duplicate_records_are_removed_without_sorting() {
        let result = translate(NativeResolverOutcome::Records(vec![v4(2, None), v4(1, None), v4(2, None)])).unwrap().unwrap();
        assert_eq!(result.iter().map(|item| item.address.bytes[7]).collect::<Vec<_>>(), vec![2, 1]);
    }

    #[test]
    fn bounds_and_canonical_names_are_enforced() {
        let too_long = vec![b'x'; MAX_CANONICAL_NAME + 1];
        assert_eq!(translate(NativeResolverOutcome::Records(vec![v4(1, Some(&too_long))])), Err(ContractError::CanonicalNameTooLong));
        assert_eq!(translate(NativeResolverOutcome::Records(vec![v4(1, Some(b"bad\0name"))])), Err(ContractError::CanonicalNameContainsNul));
        let many = (0..=MAX_ADDRINFO_RESULTS).map(|_| v4(1, None)).collect();
        assert_eq!(translate(NativeResolverOutcome::Records(many)), Err(ContractError::TooManyResults));
    }

    #[test]
    fn async_request_publishes_only_after_submit_and_completion() {
        let request = ResolverRequest::new();
        assert_eq!(request.poll(), ResolverPoll::Pending);
        assert!(!request.complete(Ok(())));
        assert!(request.submit());
        assert_eq!(request.poll(), ResolverPoll::Pending);
        assert!(request.complete(Err(WinsockResolverError::Again)));
        assert_eq!(request.poll(), ResolverPoll::Complete(Err(WinsockResolverError::Again)));
        assert!(!request.complete(Ok(())));
    }

    #[test]
    fn async_request_cancellation_is_terminal_and_reusable_only_after_reset() {
        let request = ResolverRequest::new();
        assert!(request.submit());
        assert!(request.cancel());
        assert_eq!(request.poll(), ResolverPoll::Complete(Err(WinsockResolverError::Cancelled)));
        assert!(!request.cancel());
        assert!(!request.submit());
        assert!(request.reset());
        assert!(request.submit());
        assert!(request.complete(Ok(())));
        assert_eq!(request.poll(), ResolverPoll::Complete(Ok(())));
    }

    #[test]
    fn async_request_rejects_completion_after_cancellation() {
        let request = ResolverRequest::new();
        assert!(request.submit());
        assert!(request.cancel());
        assert!(!request.complete(Err(WinsockResolverError::NoData)));
        assert_eq!(request.poll(), ResolverPoll::Complete(Err(WinsockResolverError::Cancelled)));
    }
}
