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
    let fault = match iov_fault_ordering() { Ok(d) => d, Err(v) => return v };
    let strings = match unmapped_string_arguments() { Ok(d) => d, Err(v) => return v };
    Verdict::Pass(format!("{plain} | {nested} | {fault} | {strings}"))
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

/// `KEYCTL_INSTANTIATE_IOV` gathers its payload out of user memory BEFORE it
/// consults the caller's authorisation token, so an unprivileged process — which
/// holds no token and could never instantiate anything — still learns whether
/// the copy faulted. That makes the ordering observable from userspace:
///
///   * an unreadable iovec array is EFAULT, not the EPERM the missing token
///     would give;
///   * a READABLE array whose segment points nowhere is EFAULT too, which is
///     the invariant that matters — the segment pointers are validated before
///     any byte is copied;
///   * a wholly valid vector gets past the copy and lands on EPERM, so the two
///     answers are genuinely distinguishable rather than EFAULT for everything.
///
/// Without this the whole keyring surface had no EFAULT assertion anywhere.
/// # C: O(1)
fn iov_fault_ordering() -> Result<String, Verdict> {
    /// An address no process maps. Kept far from anything the loader places.
    const UNMAPPED: usize = 0x0000_7ffe_dead_0000;
    let mut payload = *b"answer";

    // A whole iovec array that is not readable.
    let rc = keyctl_iov(UNMAPPED, 1);
    if rc.1 != libc::EFAULT { return Err(fail(&format!("iov array rc={} errno={}", rc.0, rc.1))); }

    // A readable array, one segment, pointing at unmapped memory.
    let bad = [libc::iovec { iov_base: UNMAPPED as *mut libc::c_void, iov_len: payload.len() }];
    let rc = keyctl_iov(bad.as_ptr() as usize, 1);
    if rc.1 != libc::EFAULT { return Err(fail(&format!("iov segment rc={} errno={}", rc.0, rc.1))); }

    // A valid vector: the copy succeeds and the MISSING TOKEN is what stops it.
    let good = [libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void, iov_len: payload.len() }];
    let rc = keyctl_iov(good.as_ptr() as usize, 1);
    if rc.1 != libc::EPERM { return Err(fail(&format!("iov valid rc={} errno={}", rc.0, rc.1))); }
    Ok(String::from("iov-efault ordering=copy-before-authority"))
}

/// Every syscall that takes a STRING from userspace reads it through one shared
/// reader. This drives that reader from the outside with a pointer that is in
/// the user half and mapped by nothing — the shape that used to kill the boot,
/// because a range check said "user address" and the byte read had no
/// exception-table fixup behind it.
///
/// Each of these reaches the shared reader by a different route: `openat` and
/// `stat` through the path reader, `execve` through the exec-path reader (which
/// applies the ENAMETOOLONG bound on top), `memfd_create` through the name
/// reader, and `execve`'s ARGV through the string-vector walk that used to be
/// duplicated per architecture. All must answer EFAULT with the kernel alive; a
/// regression here does not fail this assertion, it ends the boot.
/// # C: O(1)
fn unmapped_string_arguments() -> Result<String, Verdict> {
    /// An address no process maps. Kept far from anything the loader places.
    const UNMAPPED: usize = 0x0000_7ffe_dead_0000;
    let p = UNMAPPED as *const libc::c_char;
    let ok: [*const libc::c_char; 1] = [core::ptr::null()];
    let bad_argv = [UNMAPPED as *const libc::c_char, core::ptr::null()];
    // A path that always resolves, so the argv case reaches the string walk
    // instead of stopping at the image open.
    let self_exe = b"/proc/self/exe\0".as_ptr() as *const libc::c_char;

    let mut names = String::new();
    for name in ["openat", "stat", "execve-path", "execve-argv", "memfd_create"] {
        // SAFETY: every pointer here is NULL, a live local, or an address
        // deliberately chosen to be unmapped — measuring what the kernel does
        // with the last of those is the point, and glibc passes it through.
        let rc = unsafe { match name {
            "openat"       => libc::openat(libc::AT_FDCWD, p, libc::O_RDONLY) as libc::c_long,
            "stat"         => libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, p,
                                  core::ptr::null_mut::<libc::stat>(), 0),
            "execve-path"  => { libc::execve(p, ok.as_ptr(), ok.as_ptr()) as libc::c_long }
            "execve-argv"  => { libc::execve(self_exe, bad_argv.as_ptr(), ok.as_ptr()) as libc::c_long }
            _              => libc::syscall(libc::SYS_memfd_create, p, 0),
        } };
        let e = support::errno();
        if rc != -1 || e != libc::EFAULT {
            return Err(fail(&format!("{name} rc={rc} errno={e}, want -1/EFAULT")));
        }
        if !names.is_empty() { names.push(','); }
        names.push_str(name);
    }
    Ok(format!("unmapped-cstr-efault [{names}]"))
}

/// `keyctl(KEYCTL_INSTANTIATE_IOV, <no such key>, iov, ioc, 0)`, returning the
/// result and errno. The key id names nothing, which is deliberate: the
/// authority check comes first among the checks that read the key, so a
/// SUCCESSFUL copy can only end in EPERM. # C: O(1)
fn keyctl_iov(iov: usize, ioc: libc::c_long) -> (libc::c_long, i32) {
    /// A serial no key can have: the allocator hands out positive values only
    /// from a high base, and this one is never minted.
    const NO_SUCH_KEY: libc::c_long = 1;
    // SAFETY: syscall(3) is glibc's raw-syscall entry point; `iov` is either a
    // live iovec array owned by the caller or an address deliberately chosen to
    // be unmapped, which is what the call is measuring.
    let rc = unsafe {
        libc::syscall(uapi::SYS_KEYCTL, uapi::KEYCTL_INSTANTIATE_IOV, NO_SUCH_KEY,
            iov as libc::c_long, ioc, 0 as libc::c_long)
    };
    (rc, support::errno())
}

/// Whether `needle` appears anywhere in `haystack`. # C: O(n*m)
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    haystack.windows(needle.len()).any(|w| w == needle)
}
