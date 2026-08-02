//! Proof that `request_key(2)` reaches a real userspace construction helper.
//!
//! The kernel half has always been exercised through an injected actor, which
//! proves the bookkeeping but never execs anything: with no helper installed
//! every construction ends `ENOENT` -> negate, indistinguishable from a correct
//! kernel on a box without keyutils. This asks for a key that does not exist,
//! with callout info, and then READS IT BACK. A payload can only be there if the
//! kernel minted an authorisation token, ran the helper, and the helper
//! instantiated the key against that token — the whole upcall, end to end.
//!
//! The description is the one keyutils' stock configuration routes to its own
//! debugging handler, so nothing here depends on configuration we wrote
//! ourselves; the handler answers with `Debug <callout>`.
//!
//! A second case then proves the harder shape: a construction whose HELPER asks
//! the kernel for another key while the first construction is still in flight.
//! That is the nested upcall the servicing pool has to grow for — with a single
//! servicing context the inner request could only be served by the context
//! already waiting for the outer helper to exit, and both sides wedge forever.
//! Proving it hosted proves the counting rule; only a booted system proves the
//! threads.
//!
//! glibc has no `request_key`/`keyctl` wrapper, so both go through `syscall(3)` —
//! still a glibc entry point, and identical on both architectures.

use support::{Verdict, fail, fail_errno, report};

mod uapi;

/// Routed to the stock debugging handler by the shipped configuration.
const KEY_DESCRIPTION: &[u8] = b"debug:oxide-upcall\0";
/// Echoed back inside the payload, so the answer cannot be a coincidence.
const KEY_CALLOUT: &[u8] = b"oxide-proof\0";
/// The requester's own default keyring is chosen by the kernel.
const DEST_KEYRING: libc::c_long = 0;
/// `user` key type — the one the debug handler instantiates.
const KEY_TYPE: &[u8] = b"user\0";
/// Routed by the injected drop-in to a handler that requests a SECOND key
/// before answering this one.
const NESTED_DESCRIPTION: &[u8] = b"oxide-nested:upcall\0";
/// Callout for the nested case, echoed back the same way.
const NESTED_CALLOUT: &[u8] = b"oxide-nested-proof\0";
/// The nested handler reports the inner key it obtained with this marker, so a
/// payload carrying it can only come from a construction that completed INSIDE
/// another construction.
const NESTED_MARKER: &[u8] = b"inner=";
/// Upper bound on the handler's `Debug <callout>` answer.
const PAYLOAD_MAX: usize = 256;

const PROBE: &str = "REQUEST-KEY-PROBE";

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn run() -> Verdict {
    let plain = match construct("plain", KEY_DESCRIPTION, KEY_CALLOUT, &[]) {
        Ok(d) => d,
        Err(v) => return v,
    };
    // The nested case rides on the same construction path; what it adds is a
    // helper that re-enters `request_key(2)` before answering.
    let nested = match construct("nested", NESTED_DESCRIPTION, NESTED_CALLOUT, NESTED_MARKER) {
        Ok(d) => d,
        Err(v) => return v,
    };
    Verdict::Pass(format!("{plain} | {nested}"))
}

/// Ask for a key that does not exist, read the answer back, and require the
/// callout — plus `extra`, when the case carries one — to appear in it.
///
/// The echo is what makes this a proof rather than a smoke test: a payload can
/// only carry the callout if the kernel minted a token, ran the helper, and the
/// helper instantiated the key against that token. # C: O(payload)
fn construct(case: &str, desc: &[u8], callout: &[u8], extra: &[u8]) -> Result<String, Verdict> {
    // SAFETY: syscall(3) is glibc's variadic raw-syscall entry point. The four
    // arguments match request_key(2)'s signature; the three pointers are
    // NUL-terminated statics that outlive the call, and DEST_KEYRING is a
    // serial, not a pointer.
    let key = unsafe {
        libc::syscall(uapi::SYS_REQUEST_KEY,
            KEY_TYPE.as_ptr(), desc.as_ptr(), callout.as_ptr(), DEST_KEYRING)
    };
    if key < 0 { return Err(fail_errno(&format!("{case} request_key"))); }

    let mut payload = [0u8; PAYLOAD_MAX];
    // SAFETY: KEYCTL_READ writes at most `len` bytes into `payload`; one byte is
    // withheld so the answer stays NUL-terminated for the search below.
    let read = unsafe {
        libc::syscall(uapi::SYS_KEYCTL, uapi::KEYCTL_READ, key,
            payload.as_mut_ptr(), payload.len() as libc::c_long - 1, 0 as libc::c_long)
    };
    if read < 0 { return Err(fail_errno(&format!("{case} read serial={key}"))); }

    let body = payload.split(|b| *b == 0).next().unwrap_or(&[]);
    let text = String::from_utf8_lossy(body);
    // The handler answers "Debug <callout>", so the callout we sent must come
    // back inside the payload. Anything else means the key was answered by
    // something other than the helper we asked for.
    let echoed = callout.split_last().map(|(_, s)| s).unwrap_or(&[]);
    if !contains(body, echoed) || !contains(body, extra) {
        return Err(fail(&format!("{case} payload serial={key} len={read} body={text}")));
    }
    Ok(format!("{case} serial={key} len={read} payload={text}"))
}

/// Whether `needle` appears anywhere in `haystack`. # C: O(n*m)
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    haystack.windows(needle.len()).any(|w| w == needle)
}
