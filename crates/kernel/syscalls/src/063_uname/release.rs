// uname(2) `utsname` field values + the two `personality(2)`-driven overrides
// Linux applies after copying the namespace's `new_utsname` (kernel/sys.c
// `override_release` / `override_architecture`).
//
// Pure logic, no user-memory access: the syscall shim (`063_uname.rs`) copies
// what these produce, and the rules are unit-testable without a boot.

use alloc::string::String;
use alloc::vec::Vec;

/// `__NEW_UTS_LEN + 1` — each `struct new_utsname` field is 65 bytes,
/// NUL-terminated (Linux `include/uapi/linux/utsname.h`).
pub const UTSNAME_FIELD_LEN: usize = 65;
/// `sizeof(struct new_utsname)` — six 65-byte fields, no padding.
pub const UTSNAME_TOTAL_LEN: usize = UTSNAME_FIELD_LEN * 6;

/// Field index within `struct new_utsname`, in declaration order.
pub const IDX_SYSNAME:    usize = 0;
pub const IDX_NODENAME:   usize = 1;
pub const IDX_RELEASE:    usize = 2;
pub const IDX_VERSION:    usize = 3;
pub const IDX_MACHINE:    usize = 4;
pub const IDX_DOMAINNAME: usize = 5;

/// `UTS_SYSNAME`.
pub const UTS_SYSNAME: &str = "Linux";
/// `UTS_RELEASE` — the kernel version string userspace parses.
pub const UTS_RELEASE: &str = "5.15.0-oxide";
/// Kernel PATCHLEVEL of [`UTS_RELEASE`], the `LINUX_VERSION_PATCHLEVEL` that
/// `override_release` folds into its synthetic 2.6 version.
pub const UTS_RELEASE_PATCHLEVEL: u32 = 15;

/// `UTS_MACHINE` — the native architecture name.
#[cfg(target_arch = "x86_64")]
pub const UTS_MACHINE: &str = "x86_64";
#[cfg(target_arch = "aarch64")]
pub const UTS_MACHINE: &str = "aarch64";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const UTS_MACHINE: &str = "unknown";

/// `COMPAT_UTS_MACHINE` — the machine name a `PER_LINUX32` task is told it runs
/// on (`arch/x86/include/asm/compat.h`, `arch/arm64/include/asm/compat.h`;
/// arm64 little-endian takes `armv8l`).
#[cfg(target_arch = "x86_64")]
pub const COMPAT_UTS_MACHINE: &str = "i686";
#[cfg(target_arch = "aarch64")]
pub const COMPAT_UTS_MACHINE: &str = "armv8l";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const COMPAT_UTS_MACHINE: &str = "unknown";

/// Linux `init_uts_ns` seeds `nodename` and `domainname` with this, so an
/// unconfigured system reports `(none)` rather than an empty string.
pub const UTS_NONE: &[u8] = b"(none)";

/// Linux `override_release`: a task with the `UNAME26` personality is told a
/// 2.6-series release, because programs that cannot parse "Linux 3.0" and later
/// exist. The synthetic release is `2.6.<PATCHLEVEL + 60>` followed by whatever
/// tail the real release carries past its version numbers — for `5.15.0-oxide`,
/// `2.6.75-oxide`.
///
/// The tail starts at the first character of `release` that is neither a digit
/// nor a `.`, or at the third `.`, whichever comes first — Linux's exact scan.
/// # C: O(len release)
pub fn override_release(release: &str) -> String {
    let mut ndots = 0usize;
    let mut cut = release.len();
    for (i, c) in release.char_indices() {
        if c == '.' { ndots += 1; if ndots >= 3 { cut = i; break; } continue; }
        if !c.is_ascii_digit() { cut = i; break; }
    }
    let mut out = String::from("2.6.");
    push_u32(&mut out, UTS_RELEASE_PATCHLEVEL + 60);
    out.push_str(&release[cut..]);
    // scnprintf into a 65-byte buffer: the result cannot exceed the field.
    out.truncate(UTSNAME_FIELD_LEN - 1);
    out
}

fn push_u32(out: &mut String, mut n: u32) {
    if n == 0 { out.push('0'); return; }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; out.push(buf[i] as char); }
}

/// The `release` field for a task with `personality`: the native
/// [`UTS_RELEASE`] unless `UNAME26` asked for the 2.6 rewrite. # C: O(len release)
pub fn release_for(personality: u32) -> String {
    if sched::personality::wants_uname26(personality) { override_release(UTS_RELEASE) }
    else { String::from(UTS_RELEASE) }
}

/// The `machine` field for a task with `personality`: [`COMPAT_UTS_MACHINE`]
/// in the `PER_LINUX32` execution domain, else the native [`UTS_MACHINE`]
/// (Linux `override_architecture`). # C: O(1)
pub fn machine_for(personality: u32) -> &'static str {
    if sched::personality::is_linux32(personality) { COMPAT_UTS_MACHINE } else { UTS_MACHINE }
}

/// Pack one 65-byte `new_utsname` field: `src` truncated to 64 bytes then NUL
/// padded to the full width. Linux `memcpy`s a fixed-size array, so every byte
/// past the string is zero and the field is always NUL-terminated.
/// # C: O(1)
pub fn pack_field(src: &[u8]) -> [u8; UTSNAME_FIELD_LEN] {
    let mut out = [0u8; UTSNAME_FIELD_LEN];
    let n = src.len().min(UTSNAME_FIELD_LEN - 1);
    out[..n].copy_from_slice(&src[..n]);
    out
}

/// Build the whole `struct new_utsname` image the syscall copies out.
/// `nodename`/`domainname` come from the caller's UTS NAMESPACE; the remaining
/// four fields are kernel constants adjusted for the caller's personality.
/// # C: O(len fields)
pub fn build_utsname(nodename: &[u8], domainname: &[u8], version: &[u8],
                     personality: u32) -> Vec<u8> {
    let release = release_for(personality);
    let fields: [&[u8]; 6] = [
        UTS_SYSNAME.as_bytes(),
        nodename,
        release.as_bytes(),
        version,
        machine_for(personality).as_bytes(),
        domainname,
    ];
    let mut out = Vec::with_capacity(UTSNAME_TOTAL_LEN);
    for f in fields { out.extend_from_slice(&pack_field(f)); }
    out
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
