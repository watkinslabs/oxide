#!/bin/sh
[ -e /etc/oxide-init-smokes ] || exit 0
echo init-fork-exec works
for s in /bin/bare3 /bin/vim_smoke /bin/sem_smoke /bin/msg_smoke /bin/mq_smoke \
         /bin/mprotect_smoke /bin/mremap_dontunmap_smoke \
         /bin/inet6_smoke /bin/mmsg_smoke /bin/scm_smoke \
         /bin/cmdsubst_probe /bin/alarm_probe /bin/symlink_probe /bin/mount_smoke /bin/statfs_smoke /bin/dev_smoke \
         /bin/mmap_zero_smoke /bin/usleep_smoke \
         /bin/af_packet_smoke /bin/hello_dyn ; do
    [ -x "$s" ] && "$s"
done
echo pre-exit_test
/bin/exit_test
echo post-exit_test rv=$?
echo pre-bash-dynamic
/bin/bash --version 2>&1 | head -1
echo post-bash-dynamic rv=$?
echo pre-pthread-probe
timeout 10 /bin/pthread_socketpair_probe
echo post-pthread-probe rv=$?
echo pre-socketpair-fork-probe
timeout 10 /bin/socketpair_fork_probe
echo post-socketpair-fork-probe rv=$?
echo pre-hello_dyn_libc
/bin/hello_dyn_libc
echo post-hello_dyn_libc rv=$?
echo pre-libcap_probe
/bin/libcap_probe
echo post-libcap_probe rv=$?
echo pre-zstd_probe
/bin/zstd_probe
echo post-zstd_probe rv=$?
echo pre-lz4_probe
/bin/lz4_probe
echo post-lz4_probe rv=$?
echo pre-libxcrypt_probe
/bin/libxcrypt_probe
echo post-libxcrypt_probe rv=$?
echo pre-pcre2_probe
/bin/pcre2_probe
echo post-pcre2_probe rv=$?
echo pre-libseccomp_probe
/bin/libseccomp_probe
echo post-libseccomp_probe rv=$?
echo pre-utillinux_probe
/bin/utillinux_probe
echo post-utillinux_probe rv=$?
echo pre-expat_probe
/bin/expat_probe
echo post-expat_probe rv=$?
echo pre-dbus_probe
/bin/dbus_probe
echo post-dbus_probe rv=$?
echo pre-libgpgerror_probe
/bin/libgpgerror_probe
echo post-libgpgerror_probe rv=$?
echo pre-libgcrypt_probe
/bin/libgcrypt_probe
echo post-libgcrypt_probe rv=$?
echo pre-attr_probe
/bin/attr_probe
echo post-attr_probe rv=$?
echo pre-acl_probe
/bin/acl_probe
echo post-acl_probe rv=$?
echo pre-kmod_probe
/bin/kmod_probe
echo post-kmod_probe rv=$?
echo pre-openssl_probe
# aarch64: libcrypto.so hangs in its load-time constructor (before main)
# under the oxide kernel — running it would wedge rcS → no login. x86 runs
# it; arm is gated until the load hang is fixed (TASKS.md HARD blocker, D6).
/bin/openssl_probe
echo post-openssl_probe rv=$?
echo pre-libidn2_probe
/bin/libidn2_probe
echo post-libidn2_probe rv=$?
echo pre-systemd_probe
/bin/systemd_probe
echo post-systemd_probe rv=$?
echo pre-systemd-pid1
/lib/systemd/systemd --version
echo post-systemd-pid1 rv=$?
echo pre-cgroup-smoke
[ -x /bin/cgroup_smoke ] && /bin/cgroup_smoke
echo post-cgroup-smoke rv=$?
[ -x /bin/fsmount_probe ] && /bin/fsmount_probe
echo post-fsmount-probe rv=$?
[ -x /bin/memfd_seal_probe ] && /bin/memfd_seal_probe
echo post-memfd-seal-probe rv=$?
[ -x /bin/uevent_probe ] && /bin/uevent_probe
echo post-uevent-probe rv=$?
[ -x /bin/rtlink_probe ] && /bin/rtlink_probe
echo post-rtlink-probe rv=$?
# F362: CPython static-musl runs in-kernel (zip'd stdlib auto-found).
echo pre-python
[ -x /usr/bin/python3 ] && /usr/bin/python3 -c 'print("py-smoke", 6*7)'
echo post-python rv=$?
