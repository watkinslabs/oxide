# 18 Modules — v2 deferred entries

Carried at freeze 2026-05-02.

## BTF / CO-RE for kernel modules

Deferred to v1.x with BPF.

## Module compression (`.ko.zst`)

v1 lean = yes; decompress via `pagecache.read` before parse.

## Live patching (kpatch / livepatch)

Deferred to v2.

## Module parameters via sysfs writes

v1 lean = yes for those marked `0644`; `0444` parameters stay read-only after load.
