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
