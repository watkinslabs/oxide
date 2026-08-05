// `kernel.core_pattern`: what it names, and how it expands.
//
// The pattern chooses between two destinations. A plain pattern names a file.
// A pattern beginning with `|` names a PROGRAM, and the dump is written to its
// standard input — which is how a crash reporter collects dumps without giving
// every crashing process write access to a spool directory.
//
// Everything here is a pure function of the pattern plus a snapshot of the
// dying process, so the whole expansion is exercised without a kernel.

use alloc::string::String;
use alloc::vec::Vec;

use sync::{Spinlock, Tty as CoreClass};

/// The pattern. Empty means the default: a file named `core` in the working
/// directory.
static CORE_PATTERN: Spinlock<Vec<u8>, CoreClass> = Spinlock::new(Vec::new());

/// The default pattern, as `/proc/sys/kernel/core_pattern` reports it.
pub const DEFAULT_PATTERN: &[u8] = b"core\n";

/// Descriptor number a `%F` specifier resolves to. The helper starts with an
/// empty descriptor table, so this slot is always free for the dying process's
/// process descriptor.
pub const COREDUMP_PIDFD_NUMBER: i32 = 3;

/// Maximum byte count in a pathname AF_UNIX socket name, excluding its
/// terminating NUL.
const UNIX_SOCKET_PATH_MAX: usize = 107;

/// `/proc/sys/kernel/core_pattern` read hook. # C: O(len)
pub fn core_pattern() -> Vec<u8> {
    let g = CORE_PATTERN.lock();
    if g.is_empty() { DEFAULT_PATTERN.to_vec() } else { g.clone() }
}

/// `/proc/sys/kernel/core_pattern` write hook. # C: O(len)
pub fn set_core_pattern(b: &[u8]) {
    let mut g = CORE_PATTERN.lock();
    g.clear();
    g.extend_from_slice(b);
}

/// Install the pattern hooks into the process filesystem at boot. # C: O(1)
pub fn register_core_hooks() {
    procfs::hooks::set_core_pattern_hooks(core_pattern, set_core_pattern);
}

/// Where a pattern sends the dump.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CoreKind {
    /// Write the dump to a file.
    File,
    /// Pipe the dump to a program's standard input.
    Pipe,
    /// Send the dump to a listening socket.
    Socket,
}

/// Classify a pattern. # C: O(1)
pub fn kind_of(pattern: &[u8]) -> CoreKind {
    match pattern.first() {
        Some(b'|') => CoreKind::Pipe,
        Some(b'@') => CoreKind::Socket,
        _ => CoreKind::File,
    }
}

/// Everything a pattern can interpolate about the dying process. Snapshotted
/// once so the expansion cannot observe a half-torn-down process.
#[derive(Clone, Debug, Default)]
pub struct CoreContext {
    /// Signal that killed it (`%s`).
    pub signo: i32,
    /// Namespace-visible and global process id (`%p`, `%P`).
    pub vpid: u32,
    pub gpid: u32,
    /// Namespace-visible and global thread id (`%i`, `%I`).
    pub vtid: u32,
    pub gtid: u32,
    /// Real user and group (`%u`, `%g`).
    pub uid: u32,
    pub gid: u32,
    /// Whether the process was dumpable (`%d`).
    pub dumpable: i32,
    /// Wall-clock seconds at the dump (`%t`).
    pub time_secs: i64,
    /// Host name (`%h`).
    pub hostname: Vec<u8>,
    /// Command name (`%e`).
    pub comm: Vec<u8>,
    /// Program path (`%E` whole, `%f` basename).
    pub exe: Vec<u8>,
    /// Core size limit (`%c`).
    pub rlimit_core: u64,
    /// Processor it ran on (`%C`).
    pub cpu: u32,
}

/// True once the expansion emitted a `%F`, meaning the helper must be given a
/// process descriptor for the dying process at [`COREDUMP_PIDFD_NUMBER`].
#[derive(Clone, Debug, Default)]
pub struct Expanded {
    pub text: Vec<u8>,
    pub wants_pidfd: bool,
}

/// Expand one pattern fragment. `kind` decides whether `%F` is meaningful —
/// a process descriptor can only be handed to a program, so a file pattern
/// drops it.
/// # C: O(len)
pub fn expand(fragment: &[u8], cx: &CoreContext, kind: CoreKind) -> Expanded {
    let mut out = Expanded::default();
    let mut i = 0usize;
    while i < fragment.len() {
        let c = fragment[i];
        if c != b'%' { out.text.push(c); i += 1; continue; }
        // A pattern ending in a lone `%` drops it and stops.
        if i + 1 >= fragment.len() { break; }
        let spec = fragment[i + 1];
        i += 2;
        match spec {
            b'%' => out.text.push(b'%'),
            b'p' => push_u64(&mut out.text, cx.vpid as u64),
            b'P' => push_u64(&mut out.text, cx.gpid as u64),
            b'i' => push_u64(&mut out.text, cx.vtid as u64),
            b'I' => push_u64(&mut out.text, cx.gtid as u64),
            b'u' => push_u64(&mut out.text, cx.uid as u64),
            b'g' => push_u64(&mut out.text, cx.gid as u64),
            b'd' => push_i64(&mut out.text, cx.dumpable as i64),
            b's' => push_i64(&mut out.text, cx.signo as i64),
            b't' => push_i64(&mut out.text, cx.time_secs),
            b'c' => push_u64(&mut out.text, cx.rlimit_core),
            b'C' => push_u64(&mut out.text, cx.cpu as u64),
            b'h' => push_escaped(&mut out.text, &cx.hostname),
            b'e' => push_escaped(&mut out.text, &cx.comm),
            b'f' => push_escaped(&mut out.text, basename(&cx.exe)),
            b'E' => push_escaped(&mut out.text, &cx.exe),
            b'F' => {
                if kind == CoreKind::Pipe {
                    out.wants_pidfd = true;
                    push_i64(&mut out.text, COREDUMP_PIDFD_NUMBER as i64);
                }
            }
            // An unrecognised specifier contributes nothing, so a pattern
            // written for a newer kernel degrades instead of failing.
            _ => {}
        }
    }
    out
}

/// Expand a file pattern into the pathname the dump is written to. A relative
/// pattern is rooted, since the dying process's working directory is not a
/// dependable place to leave a dump.
/// # C: O(len)
pub fn file_path(pattern: &[u8], cx: &CoreContext) -> String {
    let trimmed = trim_newline(pattern);
    let expanded = expand(trimmed, cx, CoreKind::File);
    let text = vfs::path_from_bytes(&expanded.text);
    if text.is_empty() { return default_path(cx); }
    if text.starts_with('/') { return text; }
    let mut rooted = String::from("/");
    rooted.push_str(&text);
    rooted
}

/// Where a dump goes when the pattern expands to nothing at all.
/// # C: O(1)
pub fn default_path(cx: &CoreContext) -> String {
    let mut s = String::from("/core.");
    let mut digits = Vec::new();
    push_u64(&mut digits, cx.vpid as u64);
    s.push_str(&vfs::path_from_bytes(&digits));
    s
}

/// The program and argument vector a `|` pattern names.
///
/// Splitting happens BEFORE expansion, so a command name or an argument that
/// expands to text containing a space stays one argument — which is why a
/// program path with a space in it survives, and why `%e` cannot be used to
/// inject extra arguments.
/// # C: O(len)
pub fn pipe_argv(pattern: &[u8], cx: &CoreContext) -> Option<(Vec<Vec<u8>>, bool)> {
    let trimmed = trim_newline(pattern);
    if kind_of(trimmed) != CoreKind::Pipe { return None; }
    let body = &trimmed[1..];
    if body.is_empty() { return None; }
    let mut argv: Vec<Vec<u8>> = Vec::new();
    let mut wants_pidfd = false;
    for token in body.split(|b| is_space(*b)).filter(|t| !t.is_empty()) {
        let e = expand(token, cx, CoreKind::Pipe);
        wants_pidfd |= e.wants_pidfd;
        argv.push(e.text);
    }
    // A pattern that is nothing but separators names no program.
    if argv.is_empty() || argv[0].is_empty() { return None; }
    // The program must be named absolutely: the helper starts at the root of
    // the initial namespace with no search path of its own to fall back on.
    if argv[0][0] != b'/' { return None; }
    Some((argv, wants_pidfd))
}

/// Expand and validate the pathname after a direct `@` core destination.
/// # C: O(len)
pub fn socket_path(pattern: &[u8], cx: &CoreContext) -> Option<String> {
    let trimmed = trim_newline(pattern);
    if kind_of(trimmed) != CoreKind::Socket { return None; }
    let body = trimmed.strip_prefix(b"@")?;
    if body.starts_with(b"@") { return None; }
    let text = expand(body, cx, CoreKind::Socket).text;
    if text.is_empty() || text[0] != b'/' || text.len() > UNIX_SOCKET_PATH_MAX
        || text.contains(&0) || text.contains(&b' ') { return None; }
    if text.split(|b| *b == b'/').any(|part| part == b"..") { return None; }
    String::from_utf8(text).ok()
}

fn is_space(b: u8) -> bool { matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) }

fn trim_newline(p: &[u8]) -> &[u8] {
    let mut end = p.len();
    while end > 0 && (p[end - 1] == b'\n' || p[end - 1] == b'\r') { end -= 1; }
    &p[..end]
}

fn basename(p: &[u8]) -> &[u8] {
    match p.iter().rposition(|&b| b == b'/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// Append an interpolated component with the escaping a pathname component
/// needs: a separator inside it would move the dump to another directory, and a
/// component that is exactly `.` or `..` would move it up one.
fn push_escaped(out: &mut Vec<u8>, src: &[u8]) {
    let start = out.len();
    out.extend_from_slice(src);
    if out.len() == start {
        // An empty component would collapse two separators together.
        out.push(b'!');
        return;
    }
    let seg = &mut out[start..];
    if seg == b"." || seg == b".." { seg[0] = b'!'; }
    for b in seg.iter_mut() {
        if *b == b'/' { *b = b'!'; }
    }
}

fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    loop {
        buf[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 { break; }
    }
    while n > 0 { n -= 1; out.push(buf[n]); }
}

fn push_i64(out: &mut Vec<u8>, v: i64) {
    if v < 0 { out.push(b'-'); push_u64(out, v.unsigned_abs()); } else { push_u64(out, v as u64); }
}
