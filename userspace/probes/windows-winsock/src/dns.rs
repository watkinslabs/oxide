//! Resolver error conversion at the Winsock/Linux boundary.

use crate::{normalize_addrinfo_hints, wsa_code, wsa_error, NormalizedAddrInfoHints, WsaError,
    AF_INET, AF_INET6};

pub const MAX_ADDRINFO_RESULTS: usize = 32;
pub const MAX_CANONICAL_NAME: usize = 255;

const EAI_BADFLAGS: i32 = -1;
const EAI_NONAME: i32 = -2;
const EAI_AGAIN: i32 = -3;
const EAI_FAIL: i32 = -4;
const EAI_NODATA: i32 = -5;
const EAI_FAMILY: i32 = -6;
const EAI_SOCKTYPE: i32 = -7;
const EAI_SERVICE: i32 = -8;
const EAI_MEMORY: i32 = -10;
const EAI_SYSTEM: i32 = -11;

const WSAHOST_NOT_FOUND: i32 = 11_001;
const WSATRY_AGAIN: i32 = 11_002;
const WSANO_RECOVERY: i32 = 11_003;
const WSAEAFNOSUPPORT: i32 = 10_047;
const WSAESOCKTNOSUPPORT: i32 = 10_044;
const WSATYPE_NOT_FOUND: i32 = 10_109;
const WSA_NOT_ENOUGH_MEMORY: i32 = 8;

/// Address returned by the Linux-shaped resolver owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAddress { V4([u8; 4]), V6([u8; 16]) }

/// One native result before conversion to the Windows wire layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAddrInfo {
    pub flags: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub address: NativeAddress,
    pub port: u16,
    pub canon_name: Option<alloc::vec::Vec<u8>>,
}

/// Native resolver failure, kept distinct from Winsock's error namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeResolverError { Again, BadFlags, Fail, Family, Memory, NoData, Noname, Service, SockType, System(i32) }

/// The sole DNS owner. Implementations must call the Linux/native network
/// resolver; this boundary deliberately has no local table or fallback.
pub trait NativeResolver {
    fn resolve(&self, node: Option<&[u8]>, service: Option<&[u8]>, hints: NormalizedAddrInfoHints)
        -> Result<alloc::vec::Vec<NativeAddrInfo>, NativeResolverError>;
}

/// Windows-shaped address result owned by the caller after resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAddrInfo {
    pub flags: u32,
    pub family: u16,
    pub socket_type: u32,
    pub protocol: u32,
    pub address: [u8; 28],
    pub address_len: u32,
    pub canon_name: Option<alloc::vec::Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError { Invalid(WsaError), Native(i32), EmptyResult, TooManyResults,
    CanonicalNameTooLong, CanonicalNameContainsNul }

/// Delegate one Windows lookup to the native network owner and translate its
/// bounded result. No owner call means no DNS answer; no fallback is allowed.
pub fn resolve_addrinfo<R: NativeResolver>(owner: &R, node: Option<&[u8]>, service: Option<&[u8]>,
    family: u16, socket_type: u32, protocol: u32, flags: u32)
    -> Result<alloc::vec::Vec<ResolvedAddrInfo>, ResolveError> {
    if node.is_none() && service.is_none() { return Err(ResolveError::Native(EAI_NONAME)); }
    let hints = normalize_addrinfo_hints(family, socket_type, protocol, flags)
        .map_err(ResolveError::Invalid)?;
    let service = normalize_service(service);
    let records = owner.resolve(node, service, hints).map_err(native_error)?;
    if records.is_empty() { return Err(ResolveError::EmptyResult); }
    if records.len() > MAX_ADDRINFO_RESULTS { return Err(ResolveError::TooManyResults); }
    let mut output = alloc::vec::Vec::with_capacity(records.len());
    for record in records {
        if let Some(name) = &record.canon_name {
            if name.len() > MAX_CANONICAL_NAME { return Err(ResolveError::CanonicalNameTooLong); }
            if name.contains(&0) { return Err(ResolveError::CanonicalNameContainsNul); }
        }
        let (family, address_len, address) = native_sockaddr(record.address, record.port);
        let translated = ResolvedAddrInfo { flags: record.flags, family,
            socket_type: record.socket_type, protocol: record.protocol, address,
            address_len, canon_name: record.canon_name };
        if !output.contains(&translated) { output.push(translated); }
    }
    if output.is_empty() { return Err(ResolveError::EmptyResult); }
    Ok(output)
}

fn normalize_service(service: Option<&[u8]>) -> Option<&[u8]> {
    match service {
        Some(value) if value.is_empty() => Some(b"0"),
        other => other,
    }
}

fn native_error(error: NativeResolverError) -> ResolveError {
    let code = match error {
        NativeResolverError::Again => -3, NativeResolverError::BadFlags => -1,
        NativeResolverError::Fail => -4, NativeResolverError::Family => -6,
        NativeResolverError::Memory => -10, NativeResolverError::NoData => -5,
        NativeResolverError::Noname => -2, NativeResolverError::Service => -8,
        NativeResolverError::SockType => -7, NativeResolverError::System(errno) => {
            return ResolveError::Native(addrinfo_error(-11, errno));
        }
    };
    ResolveError::Native(addrinfo_error(code, 0))
}

fn native_sockaddr(address: NativeAddress, port: u16) -> (u16, u32, [u8; 28]) {
    let mut bytes = [0; 28];
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    match address {
        NativeAddress::V4(value) => {
            bytes[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            bytes[4..8].copy_from_slice(&value);
            (AF_INET, 16, bytes)
        }
        NativeAddress::V6(value) => {
            bytes[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            bytes[8..24].copy_from_slice(&value);
            (AF_INET6, 28, bytes)
        }
    }
}

/// Convert a native resolver result to the value returned by Winsock
/// `getaddrinfo`. `errno` is consulted only for `EAI_SYSTEM`; a zero errno is
/// the Wine-compatible fallback for libc implementations that lose errno.
/// # C: O(1)
pub const fn addrinfo_error(error: i32, errno: i32) -> i32 {
    match error {
        0 => 0,
        EAI_AGAIN => WSATRY_AGAIN,
        EAI_BADFLAGS => 10_022,
        EAI_FAIL => WSANO_RECOVERY,
        EAI_FAMILY => WSAEAFNOSUPPORT,
        EAI_MEMORY => WSA_NOT_ENOUGH_MEMORY,
        EAI_NODATA | EAI_NONAME => WSAHOST_NOT_FOUND,
        EAI_SERVICE => WSATYPE_NOT_FOUND,
        EAI_SOCKTYPE => WSAESOCKTNOSUPPORT,
        EAI_SYSTEM if errno == 0 => WSAHOST_NOT_FOUND,
        EAI_SYSTEM => wsa_code(wsa_error(errno)),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AI_NUMERICHOST, AF_UNSPEC};

    struct Fixture { calls: core::cell::Cell<usize>, service: core::cell::RefCell<Option<alloc::vec::Vec<u8>>>, result: Result<alloc::vec::Vec<NativeAddrInfo>, NativeResolverError> }

    impl NativeResolver for Fixture {
        fn resolve(&self, _node: Option<&[u8]>, service: Option<&[u8]>, _hints: NormalizedAddrInfoHints)
            -> Result<alloc::vec::Vec<NativeAddrInfo>, NativeResolverError> {
            self.calls.set(self.calls.get() + 1);
            self.service.replace(service.map(alloc::vec::Vec::from));
            self.result.clone()
        }
    }

    fn v4(last: u8) -> NativeAddrInfo {
        NativeAddrInfo { flags: 0, socket_type: 1, protocol: 6,
            address: NativeAddress::V4([192, 0, 2, last]), port: 443, canon_name: None }
    }

    #[test]
    fn maps_native_resolver_results_to_winsock_values() {
        assert_eq!(addrinfo_error(0, 0), 0);
        assert_eq!(addrinfo_error(EAI_AGAIN, 0), WSATRY_AGAIN);
        assert_eq!(addrinfo_error(EAI_BADFLAGS, 0), 10_022);
        assert_eq!(addrinfo_error(EAI_FAIL, 0), WSANO_RECOVERY);
        assert_eq!(addrinfo_error(EAI_FAMILY, 0), WSAEAFNOSUPPORT);
        assert_eq!(addrinfo_error(EAI_MEMORY, 0), WSA_NOT_ENOUGH_MEMORY);
        assert_eq!(addrinfo_error(EAI_SERVICE, 0), WSATYPE_NOT_FOUND);
        assert_eq!(addrinfo_error(EAI_SOCKTYPE, 0), WSAESOCKTNOSUPPORT);
    }

    #[test]
    fn both_no_name_forms_use_the_windows_host_not_found_contract() {
        assert_eq!(addrinfo_error(EAI_NONAME, 0), WSAHOST_NOT_FOUND);
        assert_eq!(addrinfo_error(EAI_NODATA, 0), WSAHOST_NOT_FOUND);
    }

    #[test]
    fn system_errors_use_errno_and_zero_errno_is_no_name() {
        assert_eq!(addrinfo_error(EAI_SYSTEM, 13), 10_013);
        assert_eq!(addrinfo_error(EAI_SYSTEM, 32), 10_054);
        assert_eq!(addrinfo_error(EAI_SYSTEM, 0), WSAHOST_NOT_FOUND);
        assert_eq!(addrinfo_error(-99, 0), -99);
    }

    #[test]
    fn lookup_calls_the_native_owner_and_preserves_order_and_hints() {
        let owner = Fixture { calls: core::cell::Cell::new(0), service: core::cell::RefCell::new(None), result: Ok(alloc::vec![v4(2), v4(1)]) };
        let result = resolve_addrinfo(&owner, Some(b"example.test"), Some(b"https"),
            AF_UNSPEC, 1, 6, AI_NUMERICHOST).unwrap();
        assert_eq!(owner.calls.get(), 1);
        assert_eq!(result.iter().map(|item| item.address[7]).collect::<alloc::vec::Vec<_>>(),
            alloc::vec![2, 1]);
        assert_eq!(result[0].family, AF_INET);
        assert_eq!(&result[0].address[2..4], &443u16.to_be_bytes());
    }

    #[test]
    fn native_failure_is_translated_without_a_second_resolver_path() {
        let owner = Fixture { calls: core::cell::Cell::new(0), service: core::cell::RefCell::new(None), result: Err(NativeResolverError::Again) };
        assert_eq!(resolve_addrinfo(&owner, Some(b"missing.test"), None, AF_UNSPEC, 0, 0, 0),
            Err(ResolveError::Native(WSATRY_AGAIN)));
        assert_eq!(owner.calls.get(), 1);
    }

    #[test]
    fn absent_names_and_empty_native_answers_fail_closed() {
        let empty = Fixture { calls: core::cell::Cell::new(0), service: core::cell::RefCell::new(None), result: Ok(alloc::vec![]) };
        assert_eq!(resolve_addrinfo(&empty, None, None, AF_UNSPEC, 0, 0, 0),
            Err(ResolveError::Native(EAI_NONAME)));
        assert_eq!(empty.calls.get(), 0);
        assert_eq!(resolve_addrinfo(&empty, Some(b"empty.test"), None, AF_UNSPEC, 0, 0, 0),
            Err(ResolveError::EmptyResult));
        assert_eq!(empty.calls.get(), 1);
    }

    #[test]
    fn malformed_native_records_are_rejected_before_publication() {
        let owner = Fixture { calls: core::cell::Cell::new(0), service: core::cell::RefCell::new(None), result: Ok(alloc::vec![NativeAddrInfo {
            flags: 0, socket_type: 1, protocol: 6, address: NativeAddress::V6([0; 16]), port: 53,
            canon_name: Some(alloc::vec![b'x'; MAX_CANONICAL_NAME + 1]),
        }]) };
        assert_eq!(resolve_addrinfo(&owner, Some(b"bad.test"), None, AF_UNSPEC, 0, 0, 0),
            Err(ResolveError::CanonicalNameTooLong));
    }

    #[test]
    fn unsupported_hints_are_rejected_before_owner_invocation() {
        let owner = Fixture { calls: core::cell::Cell::new(0), service: core::cell::RefCell::new(None), result: Ok(alloc::vec![v4(1)]) };
        assert_eq!(resolve_addrinfo(&owner, Some(b"example.test"), None, 999, 0, 0, 0),
            Err(ResolveError::Invalid(WsaError::AddressFamilyNotSupported)));
        assert_eq!(owner.calls.get(), 0);
    }

    #[test]
    fn empty_service_is_normalized_to_zero_at_native_boundary() {
        let owner = Fixture { calls: core::cell::Cell::new(0), service: core::cell::RefCell::new(None), result: Ok(alloc::vec![v4(1)]) };
        assert!(resolve_addrinfo(&owner, Some(b"localhost"), Some(b""), AF_UNSPEC, 1, 6, 0).is_ok());
        assert_eq!(owner.service.borrow().as_deref(), Some(b"0".as_slice()));
    }

    #[test]
    fn nonempty_and_absent_services_are_not_rewritten() {
        let owner = Fixture { calls: core::cell::Cell::new(0), service: core::cell::RefCell::new(None), result: Ok(alloc::vec![v4(1)]) };
        assert!(resolve_addrinfo(&owner, Some(b"localhost"), Some(b"https"), AF_UNSPEC, 1, 6, 0).is_ok());
        assert_eq!(owner.service.borrow().as_deref(), Some(b"https".as_slice()));
        assert!(resolve_addrinfo(&owner, Some(b"localhost"), None, AF_UNSPEC, 1, 6, 0).is_ok());
        assert_eq!(*owner.service.borrow(), None);
    }
}
