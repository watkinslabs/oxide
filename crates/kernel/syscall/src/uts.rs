// Kernel version identity — the ONE owner of the strings that name this
// kernel to userspace. `uname(2)`, `/proc/version`,
// `/proc/sys/kernel/{ostype,osrelease,version}`, and the module vermagic all
// derive from the macros below; a second literal anywhere is a split source of
// truth that userspace can observe directly (a libc startup path reads
// `/proc/sys/kernel/osrelease` and compares it against its configured minimum,
// while every other probe reads `uname(2)` — the two disagreeing is a
// diagnosable bug, not cosmetics).
//
// Everything derives at COMPILE time: the macros expand to literals so
// `concat!` can build the composed forms, and there is no runtime formatter to
// drift.
//
// The release number is a CAPABILITY claim: userspace feature-probes gate code
// paths on it. It states the Linux syscall/feature surface this kernel
// implements, not a build counter. `RELEASE_*` below decompose it; the
// `uname(2)` UNAME26 rewrite and `LINUX_VERSION_CODE` consumers read those
// rather than re-parsing the string.

/// `UTS_SYSNAME`. Userspace branches on this — anything but `Linux` breaks the
/// libc and service-manager paths that expect a Linux kernel.
#[macro_export]
macro_rules! uts_sysname { () => { "Linux" } }

/// `UTS_RELEASE`. Derivation of the number is recorded in the branch that set
/// it; the invariant here is that it is the only place it appears.
#[macro_export]
macro_rules! uts_release { () => { "6.19.0-oxide" } }

/// `UTS_VERSION` — the build/config banner. A build-time constant in Linux, so
/// it carries no per-boot state (a runtime-formatted value here would disagree
/// with `/proc/sys/kernel/version`, which copies the same field).
#[macro_export]
macro_rules! uts_version { () => { "#1 SMP PREEMPT oxide v0.1.0" } }

pub const UTS_SYSNAME: &str = uts_sysname!();
pub const UTS_RELEASE: &str = uts_release!();
pub const UTS_VERSION: &str = uts_version!();

/// `VERSION` / `PATCHLEVEL` / `SUBLEVEL` of [`UTS_RELEASE`].
pub const RELEASE_VERSION:    u32 = 6;
pub const RELEASE_PATCHLEVEL: u32 = 19;
pub const RELEASE_SUBLEVEL:   u32 = 0;

/// `KERNEL_VERSION(a,b,c)` packing: `(a << 16) + (b << 8) + min(c, 255)`.
/// # C: O(1)
pub const fn kernel_version(a: u32, b: u32, c: u32) -> u32 {
    (a << 16) + (b << 8) + if c > 255 { 255 } else { c }
}

/// `LINUX_VERSION_CODE` for [`UTS_RELEASE`].
pub const LINUX_VERSION_CODE: u32 =
    kernel_version(RELEASE_VERSION, RELEASE_PATCHLEVEL, RELEASE_SUBLEVEL);

/// `/proc/version` body (Linux `linux_banner`).
pub const PROC_VERSION: &str = concat!(
    uts_sysname!(), " version ", uts_release!(), " (oxide@build) ", uts_version!(), "\n");

/// `/proc/sys/kernel/ostype`, `osrelease`, `version` bodies — the same three
/// utsname fields, one per line, as the sysctl handlers report them.
pub const PROC_SYS_OSTYPE:    &str = concat!(uts_sysname!(), "\n");
pub const PROC_SYS_OSRELEASE: &str = concat!(uts_release!(), "\n");
pub const PROC_SYS_VERSION:   &str = concat!(uts_version!(), "\n");

/// Module vermagic. Linux stamps `UTS_RELEASE` into every module and refuses a
/// mismatch, so the module ABI and the reported release are ONE string; the
/// out-of-tree build headers (`kpi/include/generated/utsrelease.h`) define the
/// same value.
pub const KERNEL_VERMAGIC: &str = uts_release!();

#[cfg(test)]
mod tests {
    use super::*;

    // The release string and its decomposition cannot drift apart: the UNAME26
    // rewrite and any version-code comparison read the numbers, userspace reads
    // the string.
    #[test]
    fn release_numbers_match_the_release_string() {
        let mut it = UTS_RELEASE.split(|c: char| c == '.' || c == '-');
        assert_eq!(it.next().unwrap().parse::<u32>().unwrap(), RELEASE_VERSION);
        assert_eq!(it.next().unwrap().parse::<u32>().unwrap(), RELEASE_PATCHLEVEL);
        assert_eq!(it.next().unwrap().parse::<u32>().unwrap(), RELEASE_SUBLEVEL);
    }

    #[test]
    fn release_is_dotted_x_y_z_with_a_suffix() {
        // A libc/service-manager version parse wants `X.Y.Z` first; a release
        // that does not start with three numbers is unparseable to them.
        let head = UTS_RELEASE.split('-').next().unwrap();
        assert_eq!(head.split('.').count(), 3);
        assert!(head.split('.').all(|p| p.parse::<u32>().is_ok()));
        assert!(UTS_RELEASE.ends_with("-oxide"));
    }

    #[test]
    fn version_code_packs_like_kernel_version() {
        assert_eq!(kernel_version(6, 19, 0), 0x0006_1300);
        assert_eq!(LINUX_VERSION_CODE, kernel_version(6, 19, 0));
        // Sublevel saturates at 255 rather than carrying into the patchlevel.
        assert_eq!(kernel_version(2, 6, 300) & 0xFF, 255);
        assert_eq!(kernel_version(2, 6, 300) >> 8 & 0xFF, 6);
    }

    // Every derived body is the same string: a reader of `/proc/version`,
    // `/proc/sys/kernel/osrelease`, and `uname(2)` must not be able to tell
    // them apart.
    #[test]
    fn every_derived_body_carries_the_one_release() {
        assert!(PROC_VERSION.contains(UTS_RELEASE));
        assert!(PROC_VERSION.starts_with(UTS_SYSNAME));
        assert!(PROC_VERSION.contains(UTS_VERSION));
        assert_eq!(PROC_SYS_OSRELEASE.trim_end(), UTS_RELEASE);
        assert_eq!(PROC_SYS_OSTYPE.trim_end(), UTS_SYSNAME);
        assert_eq!(PROC_SYS_VERSION.trim_end(), UTS_VERSION);
        assert_eq!(KERNEL_VERMAGIC, UTS_RELEASE);
    }

    // The release number is a claim about the SURFACE, and these are its two
    // bounds, both taken from released Linux syscall tables:
    //
    //   floor  — every native syscall slot up to and including `listns` is
    //            routed here; `listns` first appears in the 6.19 series (it is
    //            absent from 6.17 and present in 6.19), so a claim below 6.19
    //            under-reports what a prober can already call.
    //   ceiling — `rseq_slice_yield` (slot 471) is absent from the 6.19 series
    //            and present after it, and its time-slice-extension GRANT side
    //            is NOT implemented here, so 7.0 is the first release this
    //            kernel may not claim.
    #[test]
    fn claimed_release_sits_between_the_surface_we_have_and_the_first_we_lack() {
        assert!(crate::nrs::NR_LISTNS == 470 && crate::nrs::NR_RSEQ_SLICE_YIELD == 471);
        assert!(LINUX_VERSION_CODE >= kernel_version(6, 19, 0),
            "claims less than the syscall surface routed here");
        assert!(LINUX_VERSION_CODE < kernel_version(7, 0, 0),
            "claims a release whose rseq slice-extension grant is not implemented");
    }

    #[test]
    fn every_derived_body_is_one_newline_terminated_line() {
        for body in [PROC_VERSION, PROC_SYS_OSTYPE, PROC_SYS_OSRELEASE, PROC_SYS_VERSION] {
            assert!(body.ends_with('\n'));
            assert_eq!(body.matches('\n').count(), 1);
        }
    }
}
