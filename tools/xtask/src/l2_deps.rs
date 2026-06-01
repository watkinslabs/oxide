// Track L2 systemd shared-dependency tables. Adding a cross-built dep is
// a row here (+ its vendor/<v>/build.sh, fetch script, probe .c, and an
// rcS line in assets/oxide-smokes.sh) — cmd_rootfs iterates these.

/// Shared libs to stage into /usr/lib: (vendor, real-soname, soname-link,
/// linker-link). `vendor` is the vendor/<vendor>/install-<arch>/lib dir.
pub const L2_LIBS: &[(&str, &str, &str, &str)] = &[
    ("libcap",     "libcap.so.2.69",       "libcap.so.2",       "libcap.so"),
    ("zstd",       "libzstd.so.1.5.6",     "libzstd.so.1",      "libzstd.so"),
    ("lz4",        "liblz4.so.1.9.4",      "liblz4.so.1",       "liblz4.so"),
    ("libxcrypt",  "libcrypt.so.2.0.0",    "libcrypt.so.2",     "libcrypt.so"),
    ("pcre2",      "libpcre2-8.so.0.13.0", "libpcre2-8.so.0",   "libpcre2-8.so"),
    ("libseccomp", "libseccomp.so.2.5.5",  "libseccomp.so.2",   "libseccomp.so"),
    ("util-linux", "libmount.so.1.1.0",    "libmount.so.1",     "libmount.so"),
    ("util-linux", "libblkid.so.1.1.0",    "libblkid.so.1",     "libblkid.so"),
    ("util-linux", "libuuid.so.1.3.0",     "libuuid.so.1",      "libuuid.so"),
    ("util-linux", "libsmartcols.so.1.1.0","libsmartcols.so.1", "libsmartcols.so"),
    ("expat",      "libexpat.so.1.9.2",    "libexpat.so.1",     "libexpat.so"),
    ("dbus",       "libdbus-1.so.3.32.4",  "libdbus-1.so.3",    "libdbus-1.so"),
    ("libgpg-error","libgpg-error.so.0.37.0","libgpg-error.so.0","libgpg-error.so"),
];

/// Dynamic-link probes: (vendor, probe-name, link-flags). The probe
/// `userspace/<probe>/<probe>.c` links the lib(s) and runs from rcS.
pub const L2_PROBES: &[(&str, &str, &str)] = &[
    ("libcap",     "libcap_probe",     "-lcap"),
    ("zstd",       "zstd_probe",       "-lzstd"),
    ("lz4",        "lz4_probe",        "-llz4"),
    ("libxcrypt",  "libxcrypt_probe",  "-lcrypt"),
    ("pcre2",      "pcre2_probe",      "-lpcre2-8"),
    ("libseccomp", "libseccomp_probe", "-lseccomp"),
    ("util-linux", "utillinux_probe",  "-lmount -lblkid -luuid"),
    ("expat",      "expat_probe",      "-lexpat"),
    ("dbus",       "dbus_probe",       "-ldbus-1"),
    ("libgpg-error","libgpgerror_probe","-lgpg-error"),
];
