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
/// Upper bound on the handler's `Debug <callout>` answer.
const PAYLOAD_MAX: usize = 256;

const PROBE: &str = "REQUEST-KEY-PROBE";

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn run() -> Verdict {
    // SAFETY: syscall(3) is glibc's variadic raw-syscall entry point. The four
    // arguments match request_key(2)'s signature; the three pointers are
    // NUL-terminated statics that outlive the call, and DEST_KEYRING is a
    // serial, not a pointer.
    let key = unsafe {
        libc::syscall(uapi::SYS_REQUEST_KEY,
            KEY_TYPE.as_ptr(), KEY_DESCRIPTION.as_ptr(), KEY_CALLOUT.as_ptr(), DEST_KEYRING)
    };
    if key < 0 { return fail_errno("request_key"); }

    let mut payload = [0u8; PAYLOAD_MAX];
    // SAFETY: KEYCTL_READ writes at most `len` bytes into `payload`; one byte is
    // withheld so the answer stays NUL-terminated for the search below.
    let read = unsafe {
        libc::syscall(uapi::SYS_KEYCTL, uapi::KEYCTL_READ, key,
            payload.as_mut_ptr(), payload.len() as libc::c_long - 1, 0 as libc::c_long)
    };
    if read < 0 { return fail_errno(&format!("read serial={key}")); }

    let body = payload.split(|b| *b == 0).next().unwrap_or(&[]);
    let text = String::from_utf8_lossy(body);
    // The handler answers "Debug <callout>", so the callout we sent must come
    // back inside the payload. Anything else means the key was answered by
    // something other than the helper we asked for.
    let echoed = KEY_CALLOUT.split_last().map(|(_, s)| s).unwrap_or(&[]);
    if !contains(body, echoed) {
        return fail(&format!("payload serial={key} len={read} body={text}"));
    }
    Verdict::Pass(format!("serial={key} len={read} payload={text}"))
}

/// Whether `needle` appears anywhere in `haystack`. # C: O(n*m)
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    haystack.windows(needle.len()).any(|w| w == needle)
}
