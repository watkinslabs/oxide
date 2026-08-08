//! Differential record output: `<area>|<test>|<detail>\n`, one `write(2)` per
//! line. Scraped off the serial console by `tools/boot-smoke-sockopt-diff.sh`
//! and diffed byte-for-byte against a real Linux run of this same binary, so
//! every line must be identical on a correct kernel and survive a `fork()`
//! child writing to the same fd (see `sock::priv_pair`) without duplication —
//! hence the raw unbuffered write instead of Rust's buffered `Stdout`.

use std::os::raw::c_void;

/// Write `text` + `\n` to fd 1 with `write(2)`, retrying on a short write.
/// # C: O(len)
fn emit(text: &str) {
    let mut buf = Vec::with_capacity(text.len() + 1);
    buf.extend_from_slice(text.as_bytes());
    buf.push(b'\n');
    let mut off = 0usize;
    while off < buf.len() {
        // SAFETY: buf[off..] is a valid slice of the local Vec for its
        // remaining length; write(2) never retains the pointer past the call.
        let n = unsafe {
            libc::write(1, buf[off..].as_ptr() as *const c_void, buf.len() - off)
        };
        if n <= 0 { break; }
        off += n as usize;
    }
}

/// `area|test|detail`. # C: O(len)
pub fn out(area: &str, test: &str, detail: &str) { emit(&format!("{area}|{test}|{detail}")); }

/// `area|test|rc=<rc>|errno=<NAME>(<n>)`. # C: O(len)
pub fn result(area: &str, test: &str, rc: i64, err: i32) {
    out(area, test, &format!("rc={rc}|errno={}", errname(err)));
}

/// `<NAME>(<n>)` — the shape every multi-field record uses for an errno, so a
/// divergence in the RAW number (not just the symbol) is always visible, even
/// when both sides map to the catch-all `OTHER` symbol. # C: O(1)
pub fn errname(err: i32) -> String { format!("{}({err})", errno_name(err)) }

/// The calling thread's `errno`. Delegates to `support::errno()` — the one
/// owner of that accessor across every probe in this workspace. # C: O(1)
pub fn errno() -> i32 { support::errno() }

/// Symbolic name for a captured errno. Repository text may not name external
/// implementation source, so this is the closed set of errnos the probe's own
/// call sites can produce (`01` errno table), not a derivation from a header.
/// # C: O(1)
pub fn errno_name(err: i32) -> &'static str {
    match err {
        0 => "OK",
        libc::EACCES => "EACCES",
        libc::EAGAIN => "EAGAIN",
        libc::EALREADY => "EALREADY",
        libc::EBADF => "EBADF",
        libc::EBUSY => "EBUSY",
        libc::EDOM => "EDOM",
        libc::EEXIST => "EEXIST",
        libc::EFAULT => "EFAULT",
        libc::EINVAL => "EINVAL",
        libc::ENODEV => "ENODEV",
        libc::ENOENT => "ENOENT",
        libc::ENOMEM => "ENOMEM",
        libc::ENOBUFS => "ENOBUFS",
        libc::ENOPROTOOPT => "ENOPROTOOPT",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::ENXIO => "ENXIO",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::ENOSPC => "ENOSPC",
        libc::ENOTCONN => "ENOTCONN",
        libc::EPERM => "EPERM",
        libc::ERANGE => "ERANGE",
        _ => "OTHER",
    }
}
