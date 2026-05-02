# 16 VFS — v2 deferred entries

Carried at freeze 2026-05-02.

## Negative dentry ownership

v1 lean = VFS owns; FS consulted on miss only. Documented decision.

## `O_TMPFILE`

Anonymous inode + materialize-on-link. ext4 fine; tmpfs needs tweak. v1 lean = yes.

## Idmapped mounts (`MOUNT_ATTR_IDMAP`)

Required for rootless containers. Deferred to v1.x.

## Filesystem freeze (`FIFREEZE`)

Ioctl for backup. Deferred to v1.x.
