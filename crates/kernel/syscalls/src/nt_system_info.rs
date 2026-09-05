//! NT system-information extensions owned by the native NTDLL boundary.

extern crate alloc;

use alloc::vec::Vec;

pub(crate) const SYSTEM_WINE_VERSION_INFORMATION: u32 = 1000;
const NATIVE_NTDLL_VERSION: &[u8] = b"oxide-nt";
const NATIVE_NTDLL_BUILD: &[u8] = b"native";

/// Build the NTDLL version record consumed by Wine's version initialization.
/// The four NUL-terminated fields are version, build, host system, and host
/// release; the host fields derive from the canonical Linux UTS identity.
/// # C: O(n)
pub(crate) fn wine_version_payload() -> Vec<u8> {
    let fields = [
        NATIVE_NTDLL_VERSION,
        NATIVE_NTDLL_BUILD,
        syscall::uts::UTS_SYSNAME.as_bytes(),
        syscall::uts::UTS_RELEASE.as_bytes(),
    ];
    let mut output = Vec::new();
    for field in fields {
        output.extend_from_slice(field);
        output.push(0);
    }
    output
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn dispatch(call: syscall::nt::NtCall) -> Option<u64> {
    use syscall::nt::NtService;

    if call.service != NtService::QuerySystemInformation
        || call.args.a0 as u32 != SYSTEM_WINE_VERSION_INFORMATION { return None; }
    const STATUS_SUCCESS: u64 = 0;
    const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
    const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
    const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
    let Some(current) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !current.is_nt_personality() || call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let payload = wine_version_payload();
    if call.args.a2 < payload.len() as u64 {
        if call.args.a3 != 0 && uaccess::put_user_u32(call.args.a3, payload.len() as u32).is_err() {
            return Some(STATUS_INVALID_PARAMETER);
        }
        return Some(STATUS_INFO_LENGTH_MISMATCH);
    }
    if uaccess::copy_to_user(call.args.a1, &payload).is_err() { return Some(STATUS_ACCESS_VIOLATION); }
    if call.args.a3 != 0 && uaccess::put_user_u32(call.args.a3, payload.len() as u32).is_err() {
        return Some(STATUS_INVALID_PARAMETER);
    }
    Some(STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn fields(payload: &[u8]) -> Vec<&[u8]> { payload.split(|byte| *byte == 0).collect() }

    #[test]
    fn payload_has_the_four_ntdll_version_fields() {
        let payload = wine_version_payload();
        assert_eq!(fields(&payload), vec![
            b"oxide-nt".as_slice(), b"native".as_slice(),
            syscall::uts::UTS_SYSNAME.as_bytes(), syscall::uts::UTS_RELEASE.as_bytes(), b"".as_slice(),
        ]);
    }

    #[test]
    fn payload_uses_canonical_host_identity() {
        let payload = wine_version_payload();
        assert!(payload.windows(syscall::uts::UTS_SYSNAME.len() + 1)
            .any(|window| window.starts_with(syscall::uts::UTS_SYSNAME.as_bytes())));
        assert!(payload.ends_with(&[0]));
    }
}
