// argv → cmdline serializer per `19§4`. Produces the `/proc/<pid>/cmdline`
// byte sequence: argv elements joined by NUL, with a trailing NUL. Lossy
// UTF-8: any non-ASCII byte is dropped (kept simple to stay no_std-clean
// on String::push). Real shells pass UTF-8 in practice.
//
// Lives in the sched crate alongside Task so the helper is hosted-testable
// and the kernel-side execve code path stays a single call.

use alloc::string::String;

/// Join `argv[0..]` slices with NUL separators, terminated by NUL.
/// Returns an empty `String` for an empty argv slice.
/// # C: O(total_bytes)
pub fn argv_to_cmdline(argv: &[&[u8]]) -> String {
    let total: usize = argv.iter().map(|a| a.len() + 1).sum();
    let mut s = String::with_capacity(total);
    for arg in argv {
        for &b in *arg {
            if b < 0x80 { s.push(b as char); }
        }
        s.push('\0');
    }
    s
}
