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
    ("libgcrypt",  "libgcrypt.so.20.4.3",  "libgcrypt.so.20",   "libgcrypt.so"),
    ("attr",       "libattr.so.1.1.2502",  "libattr.so.1",      "libattr.so"),
    ("acl",        "libacl.so.1.1.2302",   "libacl.so.1",       "libacl.so"),
    ("kmod",       "libkmod.so.2.4.1",     "libkmod.so.2",      "libkmod.so"),
    ("openssl",    "libcrypto.so.3",       "libcrypto.so.3",    "libcrypto.so"),
    ("openssl",    "libssl.so.3",          "libssl.so.3",       "libssl.so"),
    ("libunistring","libunistring.so.5.1.0","libunistring.so.5", "libunistring.so"),
    ("libidn2",    "libidn2.so.0.4.0",     "libidn2.so.0",      "libidn2.so"),
    ("systemd",    "libsystemd.so.0.42.0", "libsystemd.so.0",   "libsystemd.so"),
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
    ("libgcrypt",  "libgcrypt_probe",  "-lgcrypt"),
    ("attr",       "attr_probe",       "-lattr"),
    ("acl",        "acl_probe",        "-lacl"),
    ("kmod",       "kmod_probe",       "-lkmod"),
    ("openssl",    "openssl_probe",    "-lssl -lcrypto"),
    ("libidn2",    "libidn2_probe",    "-lidn2"),
    ("systemd",    "systemd_probe",    "-lsystemd"),
];

/// Track D6: systemd PID1 + its private libs + systemctl, staged as plain
/// file copies (install-rel-path, target). PID1's baked RUNPATH is the
/// build tree (skipped on target); ld-musl resolves the .so's from /usr/lib.
pub const SYSTEMD_STAGE: &[(&str, &str)] = &[
    ("lib/systemd/systemd",            "/lib/systemd/systemd"),
    ("lib/systemd/systemd-executor",   "/usr/lib/systemd/systemd-executor"),
    ("lib/libsystemd-core-259.so",     "/usr/lib/libsystemd-core-259.so"),
    ("lib/libsystemd-shared-259.so",   "/usr/lib/libsystemd-shared-259.so"),
    ("bin/systemctl",                  "/usr/bin/systemctl"),
    // F350 #5: minimal systemd unit tree (built into install-*/usr/lib/systemd/
    // system by build.sh). default.target → console-shell on /dev/console.
    ("usr/lib/systemd/system/default.target",       "/usr/lib/systemd/system/default.target"),
    ("usr/lib/systemd/system/console-shell.service", "/usr/lib/systemd/system/console-shell.service"),
    ("usr/lib/systemd/system/console-getty.service", "/usr/lib/systemd/system/console-getty.service"),
    ("usr/lib/systemd/system/sysinit.target",       "/usr/lib/systemd/system/sysinit.target"),
    ("usr/lib/systemd/system/basic.target",         "/usr/lib/systemd/system/basic.target"),
    ("usr/lib/systemd/system/multi-user.target",    "/usr/lib/systemd/system/multi-user.target"),
    ("usr/lib/systemd/system/getty.target",         "/usr/lib/systemd/system/getty.target"),
    ("usr/lib/systemd/system/getty-pre.target",     "/usr/lib/systemd/system/getty-pre.target"),
    ("usr/lib/systemd/system/sockets.target",       "/usr/lib/systemd/system/sockets.target"),
    ("usr/lib/systemd/system/paths.target",         "/usr/lib/systemd/system/paths.target"),
    ("usr/lib/systemd/system/slices.target",        "/usr/lib/systemd/system/slices.target"),
    ("usr/lib/systemd/system/timers.target",        "/usr/lib/systemd/system/timers.target"),
    ("usr/lib/systemd/system/local-fs.target",      "/usr/lib/systemd/system/local-fs.target"),
    ("usr/lib/systemd/system/local-fs-pre.target",  "/usr/lib/systemd/system/local-fs-pre.target"),
    ("usr/lib/systemd/system/swap.target",          "/usr/lib/systemd/system/swap.target"),
    ("usr/lib/systemd/system/graphical.target",     "/usr/lib/systemd/system/graphical.target"),
    ("usr/lib/systemd/system/rescue.target",        "/usr/lib/systemd/system/rescue.target"),
    ("usr/lib/systemd/system/emergency.target",     "/usr/lib/systemd/system/emergency.target"),
];
