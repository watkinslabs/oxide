//! Resolver error conversion at the Winsock/Linux boundary.

use crate::{wsa_code, wsa_error};

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
}
