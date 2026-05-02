# 19 dev/proc/sysfs — v2 deferred entries

Carried at freeze 2026-05-02.

## `/proc/sys/` schema source

v1 lean = per-domain registration with a central index (vs single static schema in `27`).

## `hidepid` default

v1 = `0` (Linux default). Userspace can tighten via `mount -o remount,hidepid=2`.

## `/proc/<pid>/io` accounting

Deferred to v1.x.

## `/proc/<pid>/oom_score` formula

v1 lean = copy Linux's exactly.
